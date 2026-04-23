/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <vector>

namespace fptn::protocol::https::utils {

inline std::vector<std::uint8_t> MakeClientChangeCipherSpec() {
    return {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
}

}  // namespace fptn::protocol::https::utils
