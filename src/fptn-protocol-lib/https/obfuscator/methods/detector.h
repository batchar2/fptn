/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls2/tls_obfuscator2.h"

namespace fptn::protocol::https::obfuscator {

inline IObfuscatorSPtr DetectObfuscator(
    const std::uint8_t* data, std::size_t size) {
  auto tls_obfuscator2 = std::make_shared<TlsObfuscator2>();
  if (tls_obfuscator2->CheckProtocol(data, size)) {
    return tls_obfuscator2;
  }

  // deprecated
  auto tls_obfuscator = std::make_shared<TlsObfuscator>();
  if (tls_obfuscator->CheckProtocol(data, size)) {
    return tls_obfuscator;
  }
  return nullptr;
}

inline std::vector<std::string> GetObfuscatorNames() { return {"tls", "none"}; }

inline std::optional<IObfuscatorSPtr> GetObfuscatorByName(
    const std::string& name) {
  if (name == "tls") {
    return std::make_shared<TlsObfuscator>();
  }
  if (name == "none") {
    return nullptr;
  }
  return std::nullopt;
}

};  // namespace fptn::protocol::https::obfuscator
