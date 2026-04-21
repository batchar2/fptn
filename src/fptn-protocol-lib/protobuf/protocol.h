/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <optional>
#include <string>

#include <boost/beast/core/flat_buffer.hpp>

#include "common/network/ip_packet.h"
#include "common/utils/utils.h"

namespace fptn::protocol::protobuf {

using ProtoPayloadOpt = std::optional<std::vector<std::uint8_t>>;

ProtoPayloadOpt GetProtoPayload(const boost::beast::flat_buffer& buffer);
ProtoPayloadOpt CreateProtoPayload(fptn::common::network::IPPacketPtr packet);
}  // namespace fptn::protocol::protobuf
