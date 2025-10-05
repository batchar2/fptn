
/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"

#include <cstring>
#include <iostream>
#include <random>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace {

constexpr std::size_t kMmaxBufferSize = 65536;

enum {
  kFptnTlsApplicationHeaderType = 0x17,
  kFptnTlsApplicationHeaderMajor = 0x03,
  kFptnTlsApplicationHeaderMinor = 0x03,

  kFptnTlsApplicationProtocolVersion = 0x01,
  kFptnTlsApplicationMagicFlag = 0x9763
};

#pragma pack(push, 1)
struct TLSAppDataRecordHeader {
  /* Standard TLS header */
  std::uint8_t headertype;
  std::uint8_t headermajor;
  std::uint8_t headerminor;
  std::uint16_t content_length;  // Must be in network byte order!

  /* FPTN TLS obfuscator protocol */
  std::uint64_t random_data;  // Must be in network byte order!
  std::uint16_t magic_flag;   // Must be in network byte order!
  std::uint8_t protocol_version;
};

struct FptnTLSProtocol {
  TLSAppDataRecordHeader header;
};
#pragma pack(pop)

std::uint16_t HostToNetwork16(std::uint16_t value) { return htons(value); }

std::uint16_t NetworkToHost16(std::uint16_t value) { return ntohs(value); }

std::uint64_t GetRandomData() {
  static std::mt19937 gen{std::random_device{}()};
  std::uniform_int_distribution<std::uint64_t> dist(1024, UINT64_MAX);
  return dist(gen);
}

}  // namespace

namespace fptn::protocol::https::obfuscator {

std::size_t TlsObfuscator::Deobfuscate(const std::uint8_t* data,
    std::size_t size,
    std::vector<std::uint8_t>& output) {
  // Add new data to buffer if provided
  if (data && size > 0) {
    // Limit total buffer size to 64KB to prevent memory exhaustion
    if (input_buffer_.size() + size > kMmaxBufferSize) {
      // If buffer would exceed 64KB, only add what fits
      std::size_t available_space = kMmaxBufferSize - input_buffer_.size();
      if (available_space > 0) {
        input_buffer_.insert(input_buffer_.end(), data, data + available_space);
      }
    } else {
      input_buffer_.insert(input_buffer_.end(), data, data + size);
    }
  }

  std::size_t total_processed = 0;
  std::size_t search_offset = 0;

  // Search for valid TLS records in the buffer
  while (
      input_buffer_.size() - search_offset >= sizeof(TLSAppDataRecordHeader)) {
    // Read potential header at current search offset
    TLSAppDataRecordHeader header = {};
    std::memcpy(&header, input_buffer_.data() + search_offset,
        sizeof(TLSAppDataRecordHeader));

    const std::uint16_t total_content_length =
        NetworkToHost16(header.content_length);
    const std::uint16_t magic_flag = NetworkToHost16(header.magic_flag);

    // Validate header fields
    bool is_valid_header =
        (header.headertype == kFptnTlsApplicationHeaderType) &&
        (header.headermajor == kFptnTlsApplicationHeaderMajor) &&
        (header.headerminor == kFptnTlsApplicationHeaderMinor) &&
        (header.protocol_version == kFptnTlsApplicationProtocolVersion) &&
        (magic_flag == kFptnTlsApplicationMagicFlag);

    if (!is_valid_header) {
      // Invalid header - shift search position by 1 byte and continue searching
      search_offset++;
      continue;
    }

    // Calculate payload size and full record size
    const std::uint16_t content_size =
        total_content_length - 11;  // Subtract header fields (8+2+1)
    const size_t full_record_size =
        sizeof(TLSAppDataRecordHeader) + content_size;

    // Check if we have a complete record at this position
    if (input_buffer_.size() - search_offset < full_record_size) {
      // Incomplete record - wait for more data
      break;
    }

    // Extract payload data from the complete record
    output.insert(output.end(),
        input_buffer_.begin() + search_offset + sizeof(TLSAppDataRecordHeader),
        input_buffer_.begin() + search_offset + sizeof(TLSAppDataRecordHeader) +
            content_size);

    // Remove the processed record from buffer starting from search_offset
    input_buffer_.erase(input_buffer_.begin() + search_offset,
        input_buffer_.begin() + search_offset + full_record_size);
    total_processed += full_record_size;
  }

  // If we searched through the entire buffer without finding valid headers,
  // clear the processed portion to prevent infinite growth
  if (search_offset > 0 && total_processed == 0) {
    // We found only invalid data - remove the searched portion
    input_buffer_.erase(
        input_buffer_.begin(), input_buffer_.begin() + search_offset);
    total_processed = search_offset;
  }
  return total_processed;
}

std::vector<std::uint8_t> TlsObfuscator::Obfuscate(
    const std::vector<std::uint8_t>& data) {
  const std::uint16_t total_content_length =
      sizeof(TLSAppDataRecordHeader::random_data) +
      sizeof(TLSAppDataRecordHeader::magic_flag) +
      sizeof(TLSAppDataRecordHeader::protocol_version) +
      static_cast<std::uint16_t>(data.size());

  TLSAppDataRecordHeader header = {};
  header.headertype = kFptnTlsApplicationHeaderType;
  header.headermajor = kFptnTlsApplicationHeaderMajor;
  header.headerminor = kFptnTlsApplicationHeaderMinor;

  // Convert to network byte order
  header.content_length = HostToNetwork16(total_content_length);
  header.random_data = GetRandomData();
  header.magic_flag = HostToNetwork16(kFptnTlsApplicationMagicFlag);
  header.protocol_version = kFptnTlsApplicationProtocolVersion;

  const auto* header_ptr = reinterpret_cast<const std::uint8_t*>(&header);
  std::vector<std::uint8_t> result;
  result.reserve(sizeof(TLSAppDataRecordHeader) + data.size());
  result.insert(
      result.end(), header_ptr, header_ptr + sizeof(TLSAppDataRecordHeader));
  result.insert(result.end(), data.begin(), data.end());

  return result;
}

void TlsObfuscator::Reset() { input_buffer_.clear(); }

bool TlsObfuscator::CheckProtocol(const std::uint8_t* data, std::size_t size) {
  if (data == nullptr || size < sizeof(TLSAppDataRecordHeader)) {
    return false;
  }

  TLSAppDataRecordHeader header = {};
  std::memcpy(&header, data, sizeof(TLSAppDataRecordHeader));

  const std::uint16_t magic_flag = NetworkToHost16(header.magic_flag);
  const std::uint16_t content_length = NetworkToHost16(header.content_length);

  bool is_valid_protocol =
      (header.headertype == kFptnTlsApplicationHeaderType) &&
      (header.headermajor == kFptnTlsApplicationHeaderMajor) &&
      (header.headerminor == kFptnTlsApplicationHeaderMinor) &&
      (header.protocol_version == kFptnTlsApplicationProtocolVersion) &&
      (magic_flag == kFptnTlsApplicationMagicFlag) &&
      (content_length >=
          (sizeof(TLSAppDataRecordHeader::random_data) +
              sizeof(TLSAppDataRecordHeader::protocol_version))) &&
      (content_length <= 16384);
  return is_valid_protocol;
}

};  // namespace fptn::protocol::https::obfuscator

// /*=============================================================================
// Copyright (c) 2024-2025 Stas Skokov
//
// Distributed under the MIT License (https://opensource.org/licenses/MIT)
// =============================================================================*/
//
// #include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"
//
// #include <cstring>
// #include <iostream>
// #include <random>
//
// #ifdef _WIN32
// #include <winsock2.h>
// #else
// #include <arpa/inet.h>
// #endif
//
// namespace {
//
// enum {
//   kFptnTlsApplicationHeaderType = 0x17,
//   kFptnTlsApplicationHeaderMajor = 0x03,
//   kFptnTlsApplicationHeaderMinor = 0x03,
//
//   kFptnTlsApplicationProtocolVersion = 0x01,
//   kFptnTlsApplicationMagicFlag = 0x9763
// };
//
// #pragma pack(push, 1)
// struct TLSAppDataRecordHeader {
//   /* Standard TLS header */
//   std::uint8_t headertype;
//   std::uint8_t headermajor;
//   std::uint8_t headerminor;
//   std::uint16_t content_length;  // Must be in network byte order!
//
//   /* FPTN TLS obfuscator protocol */
//   std::uint64_t random_data;
//   std::uint16_t magic_flag;  // Must be in network byte order!
//   std::uint8_t protocol_version;
// };
//
// constexpr std::size_t kMmaxBufferSize = 512 * 1024;
//
// constexpr std::size_t kObfuscatorHeaderSize =
//     sizeof(TLSAppDataRecordHeader::random_data) +
//     sizeof(TLSAppDataRecordHeader::magic_flag) +
//     sizeof(TLSAppDataRecordHeader::protocol_version);
//
// #pragma pack(pop)
//
// std::uint16_t HostToNetwork16(std::uint16_t value) { return htons(value); }
//
// std::uint16_t NetworkToHost16(std::uint16_t value) { return ntohs(value); }
//
// std::uint64_t GetRandomData() {
//   static std::mt19937 gen{std::random_device{}()};
//   std::uniform_int_distribution<std::uint64_t> dist(1024, UINT64_MAX);
//   return dist(gen);
// }
//
// }  // namespace
//
// namespace fptn::protocol::https::obfuscator {
//
// std::size_t TlsObfuscator::Deobfuscate(const std::uint8_t* data,
//     std::size_t size,
//     std::vector<std::uint8_t>& output) {
//   const std::lock_guard<std::mutex> lock(mutex_);  // mutex
//
//   if (data && size > 0) {
//     if (input_buffer_.size() + size > kMmaxBufferSize) {
//       std::size_t available_space = kMmaxBufferSize - input_buffer_.size();
//       if (available_space > 0) {
//         input_buffer_.insert(input_buffer_.end(), data, data +
//         available_space);
//       }
//     } else {
//       input_buffer_.insert(input_buffer_.end(), data, data + size);
//     }
//   }
//
//   std::size_t current_pos = 0;
//
//   while (input_buffer_.size() - current_pos >=
//   sizeof(TLSAppDataRecordHeader)) {
//     TLSAppDataRecordHeader header = {};
//     std::memcpy(&header, input_buffer_.data() + current_pos,
//         sizeof(TLSAppDataRecordHeader));
//
//     const std::uint16_t total_content_length =
//         NetworkToHost16(header.content_length);
//     const std::uint16_t magic_flag = NetworkToHost16(header.magic_flag);
//
//     bool is_valid_header =
//         (header.headertype == kFptnTlsApplicationHeaderType) &&
//         (header.headermajor == kFptnTlsApplicationHeaderMajor) &&
//         (header.headerminor == kFptnTlsApplicationHeaderMinor) &&
//         (header.protocol_version == kFptnTlsApplicationProtocolVersion) &&
//         (magic_flag == kFptnTlsApplicationMagicFlag);
//
//     if (!is_valid_header) {
//       if (current_pos == 0) {
//         std::cerr << "inavalid header" << std::endl;
//       }
//       current_pos++;
//       continue;
//     }
//
//     if (total_content_length < kObfuscatorHeaderSize) {
//       current_pos++;
//       continue;
//     }
//
//     const std::uint16_t content_size =
//         total_content_length - kObfuscatorHeaderSize;
//     const size_t full_record_size =
//         sizeof(TLSAppDataRecordHeader) + content_size;
//
//     if (input_buffer_.size() - current_pos < full_record_size) {
//       break;
//     }
//
//     const uint8_t* payload_start =
//         input_buffer_.data() + current_pos + sizeof(TLSAppDataRecordHeader);
//
//     output.resize(content_size);
//     output.insert(output.end(), payload_start, payload_start + content_size);
//
//     input_buffer_.erase(input_buffer_.begin(),
//         input_buffer_.begin() + current_pos + full_record_size);
//
//     std::cerr << "+";
//     return full_record_size;
//   }
//
//   if (current_pos > 0) {
//     input_buffer_.erase(
//         input_buffer_.begin(), input_buffer_.begin() + current_pos);
//     return current_pos;
//   }
//   return 0;
// }
//
// std::vector<std::uint8_t> TlsObfuscator::Obfuscate(
//     const std::vector<std::uint8_t>& data) {
//   const std::uint16_t total_content_length =
//       sizeof(TLSAppDataRecordHeader::random_data) +
//       sizeof(TLSAppDataRecordHeader::magic_flag) +
//       sizeof(TLSAppDataRecordHeader::protocol_version) +
//       static_cast<std::uint16_t>(data.size());
//
//   const std::lock_guard<std::mutex> lock(mutex_);  // mutex
//
//   TLSAppDataRecordHeader header = {};
//   header.headertype = kFptnTlsApplicationHeaderType;
//   header.headermajor = kFptnTlsApplicationHeaderMajor;
//   header.headerminor = kFptnTlsApplicationHeaderMinor;
//
//   // Convert to network byte order
//   header.content_length = HostToNetwork16(total_content_length);
//   header.random_data = GetRandomData();
//   header.magic_flag = HostToNetwork16(kFptnTlsApplicationMagicFlag);
//   header.protocol_version = kFptnTlsApplicationProtocolVersion;
//
//   const auto* header_ptr = reinterpret_cast<const std::uint8_t*>(&header);
//   std::vector<std::uint8_t> result;
//   result.reserve(sizeof(TLSAppDataRecordHeader) + data.size());
//   result.insert(
//       result.end(), header_ptr, header_ptr + sizeof(TLSAppDataRecordHeader));
//   result.insert(result.end(), data.begin(), data.end());
//
//   return result;
// }
//
// void TlsObfuscator::Reset() {
//   const std::lock_guard<std::mutex> lock(mutex_);  // mutex
//
//   input_buffer_.clear();
// }
//
// bool TlsObfuscator::CheckProtocol(const std::uint8_t* data, std::size_t size)
// {
//   if (data == nullptr || size < sizeof(TLSAppDataRecordHeader)) {
//     return false;
//   }
//
//   TLSAppDataRecordHeader header = {};
//   std::memcpy(&header, data, sizeof(TLSAppDataRecordHeader));
//
//   const std::uint16_t magic_flag = NetworkToHost16(header.magic_flag);
//   const std::uint16_t content_length =
//   NetworkToHost16(header.content_length);
//
//   bool is_valid_protocol =
//       (header.headertype == kFptnTlsApplicationHeaderType) &&
//       (header.headermajor == kFptnTlsApplicationHeaderMajor) &&
//       (header.headerminor == kFptnTlsApplicationHeaderMinor) &&
//       (header.protocol_version == kFptnTlsApplicationProtocolVersion) &&
//       (magic_flag == kFptnTlsApplicationMagicFlag) &&
//       (content_length >= (sizeof(TLSAppDataRecordHeader::random_data) +
//                              sizeof(TLSAppDataRecordHeader::protocol_version)));
//   return is_valid_protocol;
// }
//
// };  // namespace fptn::protocol::https::obfuscator
