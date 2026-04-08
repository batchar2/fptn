/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

namespace fptn::protocol::https {
enum class CensorshipStrategy : int {
  kSni = 0,
  kTlsObfuscator = 1,
  kSniRealityMode = 2,
  kSniRealityModeChrome146 = 20,
  kSniRealityModeFirefox149 = 60,
  kSniRealityModeYandex26 = 80,
  kSniRealityModeYandex25 = 81
};

inline bool IsRealityModeWithFakeHandshake(const CensorshipStrategy& strategy) {
  return strategy == CensorshipStrategy::kSniRealityMode ||
         strategy == CensorshipStrategy::kSniRealityModeChrome146 ||
         strategy == CensorshipStrategy::kSniRealityModeFirefox149 ||
         strategy == CensorshipStrategy::kSniRealityModeYandex26 ||
         strategy == CensorshipStrategy::kSniRealityModeYandex25;
}

}  // namespace fptn::protocol::https
