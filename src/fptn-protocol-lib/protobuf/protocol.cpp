/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/protobuf/protocol.h"

#include <algorithm>
#include <ctime>
#include <random>
#include <string>

#include <protocol.pb.h>    // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"
#include "common/utils/utils.h"

namespace fptn::protocol::protobuf {

std::string GetProtoPayload(const std::string& raw) {
  fptn::protocol::Message message;
  if (!message.ParseFromArray(raw.data(), static_cast<int>(raw.size()))) {
    throw ProcessingError("Failed to parse Protobuf message.");
  }
  if (message.protocol_version() != FPTN_PROTOBUF_PROTOCOL_VERSION) {
    throw UnsupportedProtocolVersion("Unsupported protocol version.");
  }
  switch (message.msg_type()) {
    case fptn::protocol::MSG_IP_PACKET:
      if (message.has_packet()) {
        return std::move(*message.mutable_packet()->mutable_payload());
      }
      throw ProcessingError("Malformed IP packet.");
    case fptn::protocol::MSG_ERROR:
      if (message.has_error()) {
        throw MessageError("Message error: " + message.error().error_msg());
      }
      throw MessageError("Malformed error message.");
    default:
      throw ProcessingError("Unknown message type.");
  }
}
std::string CreateProtoPayload(fptn::common::network::IPPacketPtr packet) {
  fptn::protocol::Message message;
  message.set_protocol_version(FPTN_PROTOBUF_PROTOCOL_VERSION);
  message.set_msg_type(fptn::protocol::MSG_IP_PACKET);

  const auto* raw_packet = packet->GetRawPacket();
  const void* data = raw_packet->getRawData();
  const auto current_size =
      static_cast<std::size_t>(raw_packet->getRawDataLen());

  message.mutable_packet()->set_payload(data, current_size);

#ifdef FPTN_ENABLE_PACKET_PADDING
  /**
   * Fill with random data to prevent issues related to TLS-inside-TLS.
   */
  if (current_size < FPTN_IP_PACKET_MAX_SIZE) {
    constexpr std::size_t kMaxPaddingBytes = 128;
    const std::size_t available_space = FPTN_IP_PACKET_MAX_SIZE - current_size;
    const std::size_t max_padding = std::min(kMaxPaddingBytes, available_space);

    if (max_padding > 0) {
      static thread_local std::mt19937 gen{std::random_device {}()};
      std::uniform_int_distribution<std::size_t> dist(0, max_padding);

      const std::size_t padding_size = dist(gen);
      if (padding_size > 0) {
        std::string padding_buffer;
        padding_buffer.resize(padding_size);

        fptn::common::utils::GenerateRandomBytes(
            reinterpret_cast<std::uint8_t*>(padding_buffer.data()), padding_size);

        message.mutable_packet()->set_padding_data(
            padding_buffer.data(), padding_size);
      }
    }
  }
#endif
  const std::size_t estimated_size = message.ByteSizeLong();
  std::string serialized_data(estimated_size, '\0');
  if (!message.SerializeToArray(
          serialized_data.data(), static_cast<int>(estimated_size))) {
    SPDLOG_ERROR("Failed to serialize Message.");
    return {};
  }
  return serialized_data;
}
}  // namespace fptn::protocol::protobuf
