/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <vector>

#include "fptn-protocol-lib/server/server_info.h"

namespace fptn::protocol::server {

std::uint64_t GetDownloadTimeMs(
    const ServerInfo& server, const std::string& sni, int timeout);

ServerInfo FindFastestServer(
    const std::string& sni, const std::vector<ServerInfo>& servers);

};  // namespace fptn::protocol::server
