/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
==============================================================================*/

#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

#include "common/client_id.h"
#include "common/network/ip_address.h"

#include "fptn-server/nat/traffic_shaper/leaky_bucket.h"
#include "nat/client_connection/client_connection.h"

namespace fptn::nat {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

using ClientConnections =
    std::unordered_map<ClientID, fptn::nat::ClientConnectionPtr>;

class ConnectionMultiplexer {
 public:
  static std::shared_ptr<ConnectionMultiplexer> Create(
      const ConnectParams& params,
      IPv4Address fake_client_ipv4,
      IPv6Address fake_client_ipv6) {
    return std::make_shared<ConnectionMultiplexer>(
        params, std::move(fake_client_ipv4), std::move(fake_client_ipv6));
  }

 public:
  ConnectionMultiplexer(const ConnectParams& params,
      IPv4Address fake_client_ipv4,
      IPv6Address fake_client_ipv6);

  bool AddClientConnection(const ConnectParams& params);

  common::network::IPPacketPtr PacketPreparingToWebsocket(
      common::network::IPPacketPtr packet);

  common::network::IPPacketPtr PacketPreparingFromWebsocket(
      common::network::IPPacketPtr packet);

  bool HasClientId(fptn::ClientID client_id) const;
  bool DelConnectionByClientId(fptn::ClientID client_id);

 public:
  [[nodiscard]]
  const std::string& Username() const;

  [[nodiscard]]
  std::size_t Size() const;

  [[nodiscard]]
  const std::string& SessionId() const;

  [[nodiscard]]
  const IPv4Address& FakeClientIPv4() const noexcept;

  [[nodiscard]]
  const IPv6Address& FakeClientIPv6() const noexcept;

 private:
  mutable std::mutex mutex_;

  const std::string username_;
  const std::string session_id_;

  const IPv4Address fake_client_ipv4_;
  const IPv6Address fake_client_ipv6_;

  fptn::nat::traffic_shaper::LeakyBucket shaper_to_websocket_;
  fptn::nat::traffic_shaper::LeakyBucket shaper_from_websocket_;

  ClientConnections connection_params_;
};

using ConnectionMultiplexerSPtr = std::shared_ptr<ConnectionMultiplexer>;

}  // namespace fptn::nat
