/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/protobuf/protocol.h"

#include <algorithm>
#include <ctime>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <boost/beast/core/flat_buffer.hpp>
#include <protocol.pb.h>    // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"
#include "common/utils/utils.h"

namespace {
const std::vector<std::uint8_t>& RandomPaddingData() {
  static const std::vector<std::uint8_t> kRandomData = [] {
    std::vector<std::uint8_t> data(FPTN_IP_PACKET_MAX_SIZE, 0);
    fptn::common::utils::GenerateRandomBytes(data.data(), data.size());
    return data;
  }();
  return kRandomData;
}

}  // namespace

namespace fptn::protocol::protobuf {

ProtoPayloadOpt GetProtoPayload(const boost::beast::flat_buffer& buffer) {
  const std::size_t total_size = buffer.size();
  if (total_size == 0) {
    SPDLOG_ERROR("Failed to parse Protobuf message: empty buffer");
    return std::nullopt;
  }

  const void* data_ptr = static_cast<const char*>(buffer.cdata().data());

  fptn::protocol::Message message;
  if (!message.ParseFromArray(data_ptr, static_cast<int>(total_size))) {
    SPDLOG_ERROR("Failed to parse Protobuf message: parse error");
    return std::nullopt;
  }

  if (message.protocol_version() != FPTN_PROTOBUF_PROTOCOL_VERSION) {
    SPDLOG_ERROR(
        "Unsupported protocol version: {}", message.protocol_version());
    return std::nullopt;
  }

  switch (message.msg_type()) {
    case fptn::protocol::MSG_IP_PACKET:
      if (message.has_packet()) {
        const auto& payload = message.packet().payload();
        std::vector<std::uint8_t> result;
        result.reserve(payload.size());
        result.assign(payload.begin(), payload.end());
        return result;
      }
      SPDLOG_ERROR("Malformed IP packet: no packet field");
      break;
    case fptn::protocol::MSG_ERROR:
      if (message.has_error()) {
        SPDLOG_ERROR("Message error: {}", message.error().error_msg());
      } else {
        SPDLOG_ERROR("Malformed error message: no error field");
      }
      break;
    default:
      SPDLOG_ERROR("Unknown message type");
  }
  return std::nullopt;
}

ProtoPayloadOpt CreateProtoPayload(fptn::common::network::IPPacketPtr packet) {
  if (!packet) {
    SPDLOG_ERROR("Cannot create proto payload: packet is null");
    return std::nullopt;
  }

  fptn::protocol::Message message;
  message.set_protocol_version(FPTN_PROTOBUF_PROTOCOL_VERSION);
  message.set_msg_type(fptn::protocol::MSG_IP_PACKET);

  const auto* raw_packet = packet->GetRawPacket();
  if (!raw_packet) {
    SPDLOG_ERROR("Cannot create proto payload: raw packet is null");
    return std::nullopt;
  }

  const void* data = raw_packet->getRawData();
  const auto current_size =
      static_cast<std::size_t>(raw_packet->getRawDataLen());

  if (!data || current_size == 0) {
    SPDLOG_ERROR("Cannot create proto payload: invalid packet data");
    return std::nullopt;
  }

  message.mutable_packet()->set_payload(data, current_size);

  if (current_size < FPTN_IP_PACKET_MAX_SIZE) {
    /**
     * Fill with random data to prevent issues related to TLS-inside-TLS.
     */
    constexpr std::size_t kMaxPaddingBytes = 128;
    const std::size_t available_space = FPTN_IP_PACKET_MAX_SIZE - current_size;
    const std::size_t padding_size =
        std::min(kMaxPaddingBytes, available_space);
    if (padding_size > 0) {
      const auto& padding_data = RandomPaddingData();
      message.mutable_packet()->set_padding_data(
          reinterpret_cast<const char*>(padding_data.data()), padding_size);
    }
  }
  const std::size_t estimated_size = message.ByteSizeLong();
  if (estimated_size == 0) {
    SPDLOG_ERROR("Failed to serialize Message: estimated size is 0");
    return std::nullopt;
  }

  std::vector<std::uint8_t> serialized_data(estimated_size);
  if (!message.SerializeToArray(
          serialized_data.data(), static_cast<int>(estimated_size))) {
    SPDLOG_ERROR("Failed to serialize Message.");
    return std::nullopt;
  }
  return serialized_data;
}

}  // namespace fptn::protocol::protobuf
