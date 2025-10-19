/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <optional>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/obfuscator/methods/none/none_obfuscator.h"
#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"

namespace fptn::protocol::https::obfuscator {

inline IObfuscatorSPtr DetectObfuscator(
    const std::uint8_t* data, std::size_t size) {
  auto tls_obfuscator = std::make_shared<TlsObfuscator>();
  if (tls_obfuscator->CheckProtocol(data, size)) {
    SPDLOG_INFO("Detected TLS obfuscator protocol - using TlsObfuscator");
    return tls_obfuscator;
  }
  SPDLOG_INFO(
      "No specific obfuscator detected - using NoneObfuscator as default");
  return std::make_shared<NoneObfuscator>();
}

inline std::vector<std::string> GetObfuscatorNames() { return {"tls", "none"}; }


inline std::optional<IObfuscatorSPtr> GetObfuscatorByName(
    const std::string& name) {
  if (name == "tls") {
    return std::make_shared<TlsObfuscator>();
  }
  if (name == "none") {
    return std::make_shared<NoneObfuscator>();
  }
  return std::nullopt;
}

};  // namespace fptn::protocol::https::obfuscator
