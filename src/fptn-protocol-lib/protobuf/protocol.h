/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <boost/beast/core/flat_buffer.hpp>

#ifdef USING_MIMALLOC
#include <mimalloc.h>  // NOLINT(build/include_order)
#endif

#include "common/network/ip_packet.h"
#include "common/utils/utils.h"

namespace fptn::protocol::protobuf {

#ifdef USING_MIMALLOC
using ProtoPayload = std::vector<std::uint8_t, mi_stl_allocator<std::uint8_t>>;
using ProtoPayloadOpt = std::optional<ProtoPayload>;
using BatchProtoPayload =
    std::vector<ProtoPayload, mi_stl_allocator<ProtoPayload>>;
#else
using ProtoPayload = std::vector<std::uint8_t>;
using ProtoPayloadOpt = std::optional<ProtoPayload>;
using BatchProtoPayload = std::vector<ProtoPayload>;
#endif

// DEPRECATED
ProtoPayloadOpt DeserializeIPPacket(const boost::beast::flat_buffer& buffer);
// DEPRECATED
ProtoPayloadOpt SerializeIPPacket(fptn::common::network::IPPacketPtr packet);

BatchProtoPayload DeserializeBatchIPPacket(
    const boost::beast::flat_buffer& buffer);
ProtoPayloadOpt SerializeBatchIPPacket(
    common::network::BatchIPPacketPtr packets);

std::optional<std::string> SerializeIPAssignmentMessage(
    const std::string& ip_v4, const std::string& ip_v6);
std::optional<std::pair<std::string, std::string>>
DeserializeIPAssignmentMessage(const std::string& message);

}  // namespace fptn::protocol::protobuf
