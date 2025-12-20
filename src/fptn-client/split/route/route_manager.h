/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "common/network/ip_address.h"

namespace fptn::split {

class RouteManager final {
 public:
  /*,fptn::common::network::IPv6Address gateway_ipv6*/
  explicit RouteManager(std::string out_interface_name,
      fptn::common::network::IPv4Address gateway_ipv4);
  ~RouteManager();

  bool AddRoutesIPv4(
      const std::vector<fptn::common::network::IPv4Address>& ips);

  bool AddRoutesIPv6(
      const std::vector<fptn::common::network::IPv6Address>& ips);

  void ClearRoutes();

 private:
  mutable std::mutex mutex_;
  std::unordered_set<std::string> added_routes_ipv4;
  std::unordered_set<std::string> added_routes_ipv6;

  const std::string out_interface_name_;
  const fptn::common::network::IPv4Address gateway_ipv4_;
  const fptn::common::network::IPv6Address gateway_ipv6_;
};

using RouteManagerPtr = std::unique_ptr<RouteManager>;

}  // namespace fptn::split
