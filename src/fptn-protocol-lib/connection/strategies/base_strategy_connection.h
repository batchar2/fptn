/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>

#include "fptn-protocol-lib/https/connection_config.h"

namespace fptn::protocol::connection::strategies {

enum class ConnectionStrategy : int {
  kLongTermConnection = 0,
  kConnectionPool = 1
};

using IPv4Address = fptn::common::network::IPv4Address;
using IPv6Address = fptn::common::network::IPv6Address;

class BaseStrategyConnection {
 public:
  explicit BaseStrategyConnection(std::string jwt_access_token,
      fptn::protocol::https::ConnectionConfig config);
  virtual ~BaseStrategyConnection() = default;

  fptn::protocol::https::ConnectionConfig Config() const;
  const std::string& JWTAccessToken() const;

 public:
  virtual void Start() = 0;

  virtual void Stop() = 0;

  virtual bool Send(fptn::common::network::IPPacketPtr packet) = 0;

  virtual bool IsStarted() = 0;

 private:
  const std::string jwt_access_token_;
  const fptn::protocol::https::ConnectionConfig config_;
};

using StrategyConnectionPtr = std::unique_ptr<BaseStrategyConnection>;

}  // namespace fptn::protocol::connection::strategies
