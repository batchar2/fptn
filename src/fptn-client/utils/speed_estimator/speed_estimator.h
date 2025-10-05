/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "fptn-client/utils/speed_estimator/server_info.h"
#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::utils::speed_estimator {

std::uint64_t GetDownloadTimeMs(const ServerInfo& server,
    const std::string& sni,
    int timeout,
    const std::string& md5_fingerprint,
    const fptn::protocol::https::obfuscator::IObfuscatorSPtr& obfuscator);

ServerInfo FindFastestServer(const std::string& sni,
    const std::vector<ServerInfo>& servers,
    const fptn::protocol::https::obfuscator::IObfuscatorSPtr& obfuscator);

};  // namespace fptn::utils::speed_estimator
