/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"

#include <string>

namespace fptn::protocol::connection::strategies {

BaseStrategyConnection::BaseStrategyConnection(std::string jwt_access_token,
    fptn::protocol::https::ConnectionConfig config)
    : jwt_access_token_(std::move(jwt_access_token)), config_(std::move(config)) {}

fptn::protocol::https::ConnectionConfig BaseStrategyConnection::Config() const {
  return config_;
}

const std::string& BaseStrategyConnection::JWTAccessToken() const {
  return jwt_access_token_;
}

}  // namespace fptn::protocol::connection::strategies
