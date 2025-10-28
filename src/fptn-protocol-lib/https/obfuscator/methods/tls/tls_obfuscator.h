/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::protocol::https::obfuscator {

class TlsObfuscator : public IObfuscator {
 public:
  TlsObfuscator() = default;
  ~TlsObfuscator() override = default;

  std::size_t Deobfuscate(const std::uint8_t* data,
      std::size_t size,
      std::vector<std::uint8_t>& output) override;
  std::vector<std::uint8_t> Obfuscate(
      const std::vector<std::uint8_t>& data) override;
  void Reset() override;

  bool CheckProtocol(const std::uint8_t* data, std::size_t size) override;

 private:
  mutable std::mutex mutex_;
  std::vector<uint8_t> input_buffer_;
};

};  // namespace fptn::protocol::https::obfuscator
