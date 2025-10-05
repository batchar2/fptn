/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace fptn::protocol::https::obfuscator {
class IObfuscator {
 public:
  virtual ~IObfuscator() = default;

  virtual std::size_t Deobfuscate(const std::uint8_t* data,
      std::size_t size,
      std::vector<std::uint8_t>& output) = 0;

  virtual std::vector<std::uint8_t> Obfuscate(
      const std::vector<std::uint8_t>& data) = 0;
  virtual void Reset() = 0;

  virtual bool CheckProtocol(const std::uint8_t* data, std::size_t size) = 0;
};

using IObfuscatorSPtr = std::shared_ptr<IObfuscator>;

};  // namespace fptn::protocol::https::obfuscator
