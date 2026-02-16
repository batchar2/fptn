/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>

#include "fptn-protocol-lib/connection/strategies/base_strategy_connection.h"
#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

namespace fptn::protocol::connection::strategies {

class ConnectionPool : public BaseStrategyConnection {
 public:
  static std::unique_ptr<ConnectionPool> Create(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config) {
    return std::make_unique<ConnectionPool>(
        std::move(jwt_access_token), std::move(config));
  }

  explicit ConnectionPool(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config);
  ~ConnectionPool() override;

 public:
  void Start() override;

  void Stop() override;

  bool Send(fptn::common::network::IPPacketPtr packet) override;

  bool IsStarted() override;

 private:
  mutable std::mutex mutex_;
  fptn::protocol::https::WebsocketClientPtr websocket_client_;
};

}  // namespace fptn::protocol::connection::strategies
