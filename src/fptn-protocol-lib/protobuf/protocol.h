/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <boost/beast/core/flat_buffer.hpp>

#include "common/network/ip_packet.h"
#include "common/utils/utils.h"

namespace fptn::protocol::protobuf {

using ProtoPayloadOpt = std::optional<std::vector<std::uint8_t>>;
using BatchIPPacket = std::vector<fptn::common::network::IPPacketPtr>;

// DEPRECATED
ProtoPayloadOpt DeserializeIPPacket(const boost::beast::flat_buffer& buffer);
// DEPRECATED
ProtoPayloadOpt SerializeIPPacket(fptn::common::network::IPPacketPtr packet);

std::vector<ProtoPayloadOpt> DeserializeBatchIPPacket(
    const boost::beast::flat_buffer& buffer);
ProtoPayloadOpt SerializeBatchIPPacket(BatchIPPacket packets);

std::optional<std::string> GenerateIPAssignmentMessage(
    const std::string& ip_v4, const std::string& ip_v6);
std::optional<std::pair<std::string, std::string>> ParseIPAssignmentMessage(
    const std::string& message);

}  // namespace fptn::protocol::protobuf
