/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <vector>

#include "server/server.h"

namespace fptn::client::protocol::lib::server {

std::uint64_t GetDownloadTimeMs(
    const fptn::client::protocol::lib::server::Server& server,
    const std::string& sni,
    int timeout);

Server FindFastestServer(
    const std::string& sni, const std::vector<Server>& servers);

};  // namespace fptn::client::protocol::lib::server
