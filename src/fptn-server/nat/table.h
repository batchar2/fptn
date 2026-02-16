/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include "common/network/ip_address.h"
#include "common/network/ipv4_generator.h"
#include "common/network/ipv6_generator.h"

#include "connect_params.h"
#include "connection_multiplexer/connection_multiplexer.h"
#include "nat/client_connection/client_connection.h"
#include "nat/statistic/metrics.h"
#include "nat/traffic_shaper/leaky_bucket.h"

namespace fptn::nat {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

using NatMultiplexers =
    std::unordered_map<std::string, ConnectionMultiplexerSPtr>;

class Table final {
  using IPv4INT = std::uint32_t;

 public:
  Table(IPv4Address tun_ipv4,
      IPv4Address tun_ipv4_network_address,
      std::uint32_t tun_network_ipv4_mask,
      IPv6Address tun_ipv6,
      IPv6Address tun_ipv6_network_address,
      std::uint32_t tun_network_ipv6_mask);

  ConnectionMultiplexerSPtr AddConnection(
      const fptn::nat::ConnectParams& mod_params);

  bool DelConnectionByClientId(ClientID client_id) noexcept;

  void UpdateStatistic(const fptn::statistic::MetricsSPtr& prometheus) noexcept;

 public:
  fptn::nat::ConnectionMultiplexerSPtr GetConnectionMultiplexerByFakeIPv4(
      const IPv4Address& ip) noexcept;
  fptn::nat::ConnectionMultiplexerSPtr GetConnectionMultiplexerByFakeIPv6(
      const IPv6Address& ip) noexcept;
  fptn::nat::ConnectionMultiplexerSPtr GetConnectionMultiplexerByClientId(
      ClientID clientId) noexcept;

  std::size_t GetNumberActiveSessionByUsername(const std::string& username) noexcept;

 protected:
  std::optional<IPv4Address> GetUniqueIPv4Address() noexcept;
  std::optional<IPv6Address> GetUniqueIPv6Address() noexcept;

 private:
  mutable std::mutex mutex_;
  std::uint32_t client_number_;

  const fptn::common::network::IPv4Address tun_ipv4_;
  const fptn::common::network::IPv4Address tun_ipv4_network_address_;
  const std::uint32_t tun_network_ipv4_mask_;

  const fptn::common::network::IPv6Address tun_ipv6_;
  const fptn::common::network::IPv6Address tun_ipv6_network_address_;

  const std::uint32_t tun_network_ipv6_mask_;

  fptn::common::network::IPv4AddressGenerator ipv4_generator_;
  fptn::common::network::IPv6AddressGenerator ipv6_generator_;

  // DO NOT REMOVE
  // std::unordered_map<std::string, ConnectionMultiplexerSPtr>
  //     session_id_to_connections_;  // session_id -> multiplexor
  // std::unordered_map<IPv4INT, ConnectionMultiplexerSPtr>
  //     ipv4_to_mplxs_;  // ipv4
  // std::unordered_map<std::string, ConnectionMultiplexerSPtr>
  //     ipv6_to_mplxs_;  // ipv6
  NatMultiplexers multiplexers_;
};

typedef std::shared_ptr<Table> TableSPtr;

}  // namespace fptn::nat
