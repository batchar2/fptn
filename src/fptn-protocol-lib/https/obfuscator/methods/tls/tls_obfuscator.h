/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::protocol::https::obfuscator {

class TlsObfuscator : public IObfuscator {
 public:
  TlsObfuscator() = default;
  ~TlsObfuscator() override = default;

  bool AddData(const std::uint8_t* data, std::size_t size) override;

  PreparedData Deobfuscate() override;
  PreparedData Obfuscate(const std::uint8_t* data, std::size_t size) override;
  void Reset() override;

  bool HasPendingData() const override;

  bool CheckProtocol(const std::uint8_t* data, std::size_t size) override;

  std::shared_ptr<IObfuscator> Clone() const override;

 private:
  std::vector<uint8_t> input_buffer_;
};

};  // namespace fptn::protocol::https::obfuscator
