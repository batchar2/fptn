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
  if (!message.ParseFromString(raw)) {
    throw ProcessingError("Failed to parse Protobuf message.");
  }
  if (message.protocol_version() != FPTN_PROTOBUF_PROTOCOL_VERSION) {
    throw UnsupportedProtocolVersion("Unsupported protocol version.");
  }

  if (message.msg_type() == fptn::protocol::MSG_ERROR) {
    if (message.has_error()) {
      const auto& error = message.error();
      throw MessageError("Message error  " + error.error_msg());
    }
    throw MessageError("Malformed error message.");
  }

  if (message.msg_type() == fptn::protocol::MSG_IP_PACKET) {
    if (message.has_packet()) {
      const auto& packet = message.packet();
      return std::string(packet.payload().data(), packet.payload().size());
    }
    throw ProcessingError("Malformed IP packet.");
  }
  throw ProcessingError("Unknown message type.");
}

std::string CreateProtoPayload(fptn::common::network::IPPacketPtr packet) {
  fptn::protocol::Message message;

  message.set_protocol_version(FPTN_PROTOBUF_PROTOCOL_VERSION);
  message.set_msg_type(fptn::protocol::MSG_IP_PACKET);

  const auto* raw_packet = packet->GetRawPacket();
  const void* data =
      static_cast<const void*>(raw_packet->getRawData());  // NOLINT
  const auto len = raw_packet->getRawDataLen();

  fptn::protocol::IPPacket* ip_packet_payload = message.mutable_packet();
  ip_packet_payload->set_payload(data, len);

#ifdef FPTN_ENABLE_PACKET_PADDING
  /**
   * Fill with random data to prevent issues related to TLS-inside-TLS.
   */
  static const std::string kRandomData =
      fptn::common::utils::GenerateRandomString(FPTN_IP_PACKET_MAX_SIZE);
  const std::size_t current_payload_size = ip_packet_payload->payload().size();

  if (current_payload_size < FPTN_IP_PACKET_MAX_SIZE) {
    static std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<std::size_t> dist(
        current_payload_size, FPTN_IP_PACKET_MAX_SIZE);

    const std::size_t random_length = dist(gen);
    const std::size_t padding_size = random_length - current_payload_size;

    ip_packet_payload->set_padding_data(
        kRandomData.substr(current_payload_size, padding_size));
  }
#endif
  std::string serialized_data;
  if (!message.SerializeToString(&serialized_data)) {
    SPDLOG_ERROR("Failed to serialize Message.");
    return {};
  }
  return serialized_data;
}
}  // namespace fptn::protocol::protobuf
