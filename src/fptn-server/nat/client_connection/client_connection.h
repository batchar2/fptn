/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>

#include "nat/connect_params.h"

namespace fptn::nat {

class ClientConnection final {
 public:
  static std::unique_ptr<ClientConnection> Create(
      fptn::nat::ConnectParams params) {
    return std::make_unique<ClientConnection>(std::move(params));
  }

 public:
  ClientConnection(fptn::nat::ConnectParams params);

  const fptn::nat::ConnectParams& Params() const noexcept;

 private:
  const fptn::nat::ConnectParams params_;
};

using ClientConnectionPtr = std::unique_ptr<ClientConnection>;

}  // namespace fptn::client
