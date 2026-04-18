/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

namespace fptn::protocol::https {
enum class CensorshipStrategy : int {
  kSni = 0,
  kTlsObfuscator = 1,
  kSniRealityMode = 2,
  /* Chrome */
  kSniRealityModeChrome147 = 20,
  kSniRealityModeChrome146 = 21,
  kSniRealityModeChrome145 = 22,
  /* Firefox */
  kSniRealityModeFirefox149 = 60,
  /* Yandex Browser */
  kSniRealityModeYandex26 = 80,
  kSniRealityModeYandex25 = 81,
  kSniRealityModeYandex24 = 82,
  /* Safari */
  kSniRealityModeSafari26 = 100,
};

inline bool IsRealityModeWithFakeHandshake(const CensorshipStrategy& strategy) {
  return strategy == CensorshipStrategy::kSniRealityMode ||
         strategy == CensorshipStrategy::kSniRealityModeChrome147 ||
         strategy == CensorshipStrategy::kSniRealityModeChrome146 ||
         strategy == CensorshipStrategy::kSniRealityModeChrome145 ||
         strategy == CensorshipStrategy::kSniRealityModeFirefox149 ||
         strategy == CensorshipStrategy::kSniRealityModeYandex26 ||
         strategy == CensorshipStrategy::kSniRealityModeYandex25 ||
         strategy == CensorshipStrategy::kSniRealityModeYandex24 ||
         strategy == CensorshipStrategy::kSniRealityModeSafari26;
}

}  // namespace fptn::protocol::https
