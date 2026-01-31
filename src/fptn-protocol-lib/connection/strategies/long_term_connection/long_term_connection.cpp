/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/strategies/long_term_connection/long_term_connection.h"

namespace fptn::protocol::connection::strategies {

LongTermConnection::LongTermConnection(std::string jwt_access_token,
    fptn::protocol::https::ConnectionConfig config)
    : BaseStrategyConnection(std::move(jwt_access_token), std::move(config)) {}

LongTermConnection::~LongTermConnection() {
  Stop();  // NOLINT
}

void LongTermConnection::Start() {
  websocket_client_ = std::make_unique<fptn::protocol::https::WebsocketClient>(
      JWTAccessToken(), Config());
  websocket_client_->Run();
}

void LongTermConnection::Stop() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (websocket_client_) {
    websocket_client_->Stop();
    websocket_client_.reset();
  }
}

bool LongTermConnection::Send(fptn::common::network::IPPacketPtr packet) {
  if (websocket_client_) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress knownConditionTrueFalse
    return websocket_client_ && websocket_client_->Send(std::move(packet));
  }
  return false;
}

bool LongTermConnection::IsStarted() { return true; }

}  // namespace fptn::protocol::connection::strategies
