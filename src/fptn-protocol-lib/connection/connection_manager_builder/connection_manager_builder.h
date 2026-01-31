/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <functional>
#include <memory>
#include <string>

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/connection/connection_manager/connection_manager.h"
#include "fptn-protocol-lib/https/connection_config.h"

namespace fptn::protocol::connection {

class ConnectionManagerBuilder {
 public:
  ConnectionManagerBuilder();

  ConnectionManagerBuilder& SetConnectionStrategyType(
      strategies::ConnectionStrategy connection_strategy);

  ConnectionManagerBuilder& SetServer(const IPv4Address& ip, int port);

  ConnectionManagerBuilder& SetSNI(const std::string& sni);

  ConnectionManagerBuilder& SetServerFingerprint(
      const std::string& md5_fingerprint);

  ConnectionManagerBuilder& SetTunInterface(
      const IPv4Address& ipv4, const IPv6Address& ipv6);

  ConnectionManagerBuilder& SetCensorshipStrategy(
      fptn::protocol::https::HttpsInitConnectionStrategy strategy);

  ConnectionManagerBuilder& SetOnConnectedCallback(
      const fptn::protocol::https::OnConnectedCallback& callback);

  ConnectionManagerBuilder& SetMaxReconnections(int max_attempts);

  ConnectionManagerBuilder& SetPoolSize(std::size_t pool_size);

  ConnectionManagerBuilder& SetConnectionTimeout(int timeout_ms);

  ConnectionManagerPtr Build();

 private:
  strategies::ConnectionStrategy connection_strategy_type_ =
      strategies::ConnectionStrategy::kLongTermConnection;
  fptn::protocol::https::ConnectionConfig config_;
};

}  // namespace fptn::protocol::connection
