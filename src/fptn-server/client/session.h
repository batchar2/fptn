/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/
#pragma once

#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>

#include <pcapplusplus/EthLayer.h>   // NOLINT(build/include_order)
#include <pcapplusplus/IPv4Layer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/Packet.h>     // NOLINT(build/include_order)

#include "common/client_id.h"

#include "traffic_shaper/leaky_bucket.h"

namespace fptn::client {

class Session final {
 public:
  Session(ClientID client_id,
      std::string user_name,
      const pcpp::IPv4Address& client_ipv4,
      const pcpp::IPv4Address& fake_client_ipv4,
      const pcpp::IPv6Address& client_ipv6,
      const pcpp::IPv6Address& fake_client_ipv6,
      fptn::traffic_shaper::LeakyBucketSPtr to_client,
      fptn::traffic_shaper::LeakyBucketSPtr from_client);
  [[nodiscard]] const ClientID& ClientId() const noexcept;

  [[nodiscard]] const std::string& UserName() const noexcept;

  [[nodiscard]] const pcpp::IPv4Address& ClientIPv4() const noexcept;
  [[nodiscard]] const pcpp::IPv4Address& FakeClientIPv4() const noexcept;
  [[nodiscard]] const pcpp::IPv6Address& ClientIPv6() const noexcept;
  [[nodiscard]] const pcpp::IPv6Address& FakeClientIPv6() const noexcept;

  fptn::traffic_shaper::LeakyBucketSPtr& TrafficShaperToClient() noexcept;
  fptn::traffic_shaper::LeakyBucketSPtr& TrafficShaperFromClient() noexcept;

  fptn::common::network::IPPacketPtr ChangeIPAddressToClientIP(
      fptn::common::network::IPPacketPtr packet) noexcept;
  fptn::common::network::IPPacketPtr ChangeIPAddressToFakeIP(
      fptn::common::network::IPPacketPtr packet) noexcept;

 private:
  const ClientID client_id_;
  const std::string user_name_;
  const pcpp::IPv4Address client_ipv4_;
  const pcpp::IPv4Address fake_client_ipv4_;
  const pcpp::IPv6Address client_ipv6_;
  const pcpp::IPv6Address fake_client_ipv6_;

  fptn::traffic_shaper::LeakyBucketSPtr to_client_;
  fptn::traffic_shaper::LeakyBucketSPtr from_client_;
};

using SessionSPtr = std::shared_ptr<Session>;

}  // namespace fptn::client
