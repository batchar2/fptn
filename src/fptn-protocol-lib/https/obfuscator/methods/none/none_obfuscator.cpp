
/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/obfuscator/methods/none/none_obfuscator.h"

#include <random>
#include <vector>

namespace fptn::protocol::https::obfuscator {

std::vector<std::uint8_t> NoneObfuscator::Deobfuscate(
    const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> output;
  output.reserve(size);
  output.insert(output.end(), data, data + size);
  return output;
}

std::vector<std::uint8_t> NoneObfuscator::Obfuscate(
    const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> output;
  output.reserve(size);
  output.insert(output.end(), data, data + size);
  return output;
}

void NoneObfuscator::Reset() {
  // Nothing to reset for None obfuscator
}

bool NoneObfuscator::CheckProtocol(const std::uint8_t* data, std::size_t size) {
  (void)data;
  (void)size;
  return true;
}

};  // namespace fptn::protocol::https::obfuscator
