/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <vector>

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::protocol::https::obfuscator {

class NoneObfuscator : public IObfuscator {
 public:
  NoneObfuscator() = default;
  ~NoneObfuscator() override = default;

  std::vector<std::uint8_t> Deobfuscate(
      const std::uint8_t* data, std::size_t size) override;
  std::vector<std::uint8_t> Obfuscate(
      const std::uint8_t* data, std::size_t size) override;
  void Reset() override;

  bool CheckProtocol(const std::uint8_t* data, std::size_t size) override;
};

};  // namespace fptn::protocol::https::obfuscator
