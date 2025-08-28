/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/protobuf/protocol.h"

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
        const auto& payload = message.packet().payload();
        return std::string(payload.data(), payload.size());
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
  const auto len = raw_packet->getRawDataLen();

  message.mutable_packet()->set_payload(data, len);

#ifdef FPTN_ENABLE_PACKET_PADDING
  /**
   * Fill with random data to prevent issues related to TLS-inside-TLS.
   */
  static thread_local std::mt19937 gen{std::random_device {}()};
  static thread_local std::uniform_int_distribution<std::size_t> dist(
      0, FPTN_IP_PACKET_MAX_SIZE);

  const std::size_t current_size = len;
  if (current_size < FPTN_IP_PACKET_MAX_SIZE) {
    const std::size_t padding_size =
        dist(gen) % (FPTN_IP_PACKET_MAX_SIZE - current_size + 1);

    std::string padding_buffer;
    if (padding_buffer.capacity() < padding_size) {
      padding_buffer.reserve(FPTN_IP_PACKET_MAX_SIZE);
      padding_buffer.resize(padding_size);
      std::generate_n(padding_buffer.begin(), padding_size,
          []() { return static_cast<char>(gen() % 256); });
    }
    message.mutable_packet()->set_padding_data(
        padding_buffer.data(), padding_size);
  }
#endif

  const std::size_t estimated_size = message.ByteSizeLong();
  std::string serialized_data;
  serialized_data.reserve(estimated_size + 32);

  if (!message.SerializeToString(&serialized_data)) {
    SPDLOG_ERROR("Failed to serialize Message.");
    return {};
  }
  return serialized_data;
}
}  // namespace fptn::protocol::protobuf
