/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "nat/client_connection/client_connection.h"

#include "common/network/ip_packet.h"

#include "nat/connect_params.h"

namespace fptn::nat {

ClientConnection::ClientConnection(fptn::nat::ConnectParams params)
    : params_(std::move(params)) {}

const fptn::nat::ConnectParams& ClientConnection::Params() const noexcept {
  return params_;
}

}  // namespace fptn::nat
