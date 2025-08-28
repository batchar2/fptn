/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>

#include <pcapplusplus/EthLayer.h>   // NOLINT(build/include_order)
#include <pcapplusplus/IPv4Layer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/Packet.h>     // NOLINT(build/include_order)

#include "common/network/ip_address.h"
#include "common/network/ipv4_generator.h"
#include "common/network/ipv6_generator.h"

#include "client/session.h"
#include "statistic/metrics.h"
#include "traffic_shaper/leaky_bucket.h"

namespace fptn::nat {

class Table final {
  using IPv4INT = std::uint32_t;

 public:
  Table(fptn::common::network::IPv4Address tun_ipv4,
      fptn::common::network::IPv4Address tun_ipv4_network_address,
      std::uint32_t tun_network_ipv4_mask,
      fptn::common::network::IPv6Address tun_ipv6,
      fptn::common::network::IPv6Address tun_ipv6_network_address,
      std::uint32_t tun_network_ipv6_mask);

  fptn::client::SessionSPtr CreateClientSession(ClientID client_id,
      const std::string& user_name,
      const fptn::common::network::IPv4Address& client_ipv4,
      const fptn::common::network::IPv6Address& client_ipv6,
      const fptn::traffic_shaper::LeakyBucketSPtr& to_client,
      const fptn::traffic_shaper::LeakyBucketSPtr& from_client);
  bool DelClientSession(ClientID client_id);
  void UpdateStatistic(const fptn::statistic::MetricsSPtr& prometheus);

 public:
  fptn::client::SessionSPtr GetSessionByFakeIPv4(
      const fptn::common::network::IPv4Address& ip) noexcept;
  fptn::client::SessionSPtr GetSessionByFakeIPv6(
      const fptn::common::network::IPv6Address& ip) noexcept;
  fptn::client::SessionSPtr GetSessionByClientId(ClientID clientId) noexcept;

  std::size_t GetNumberActiveSessionByUsername(const std::string& username);

 protected:
  fptn::common::network::IPv4Address GetUniqueIPv4Address();
  fptn::common::network::IPv6Address GetUniqueIPv6Address();

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


  std::unordered_map<IPv4INT, fptn::client::SessionSPtr>
      ipv4_to_sessions_;  // ipv4
  std::unordered_map<std::string, fptn::client::SessionSPtr>
      ipv6_to_sessions_;  // ipv6
  std::unordered_map<ClientID, fptn::client::SessionSPtr>
      client_id_to_sessions_;
};

typedef std::shared_ptr<Table> TableSPtr;

}  // namespace fptn::nat
