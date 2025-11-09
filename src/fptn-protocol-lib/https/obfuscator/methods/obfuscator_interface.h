/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace fptn::protocol::https::obfuscator {

using PreparedData = std::optional<std::vector<std::uint8_t>>;

class IObfuscator {
 public:
  virtual ~IObfuscator() = default;

  virtual bool AddData(const std::uint8_t* data, std::size_t size) = 0;

  virtual PreparedData Deobfuscate() = 0;

  virtual PreparedData Obfuscate(
      const std::uint8_t* data, std::size_t size) = 0;
  virtual void Reset() = 0;

  virtual bool HasPendingData() const = 0;

  virtual bool CheckProtocol(const std::uint8_t* data, std::size_t size) = 0;
};

using IObfuscatorSPtr = std::shared_ptr<IObfuscator>;

};  // namespace fptn::protocol::https::obfuscator
