/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

namespace fptn::protocol::https {
enum class CensorshipStrategy : int {
  kSni = 0,
  kTlsObfuscator = 1,
  kSniRealityMode = 2
};
}  // namespace fptn::protocol::https
