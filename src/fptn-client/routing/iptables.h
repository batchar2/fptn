/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>

#include "common/network/ip_address.h"

namespace fptn::routing {
std::string GetDefaultNetworkInterfaceName();
fptn::common::network::IPv4Address GetDefaultGatewayIPAddress();
fptn::common::network::IPv4Address ResolveDomain(const std::string& domain);

class IPTables final {
 public:
  IPTables(std::string out_interface_name,
      std::string tun_interface_name,
      fptn::common::network::IPv4Address vpn_server_ip,
      fptn::common::network::IPv4Address dns_server_ipv4,
      fptn::common::network::IPv6Address dns_server_ipv6,
      fptn::common::network::IPv4Address gateway_ip,
      fptn::common::network::IPv4Address tun_interface_address_ipv4,
      fptn::common::network::IPv6Address tun_interface_address_ipv6);
  ~IPTables();
  bool Apply();
  bool Clean();

 private:
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  const std::string out_interface_name_;
  const std::string tun_interface_name_;
  const fptn::common::network::IPv4Address vpn_server_ip_;
  const fptn::common::network::IPv4Address dns_server_ipv4_;
  const fptn::common::network::IPv6Address dns_server_ipv6_;
  const fptn::common::network::IPv4Address gateway_ip_;
  const fptn::common::network::IPv4Address tun_interface_address_ipv4_;
  const fptn::common::network::IPv6Address tun_interface_address_ipv6_;

 private:
  std::string detected_out_interface_name_;
  fptn::common::network::IPv4Address detected_gateway_ip_;
};

using IPTablesPtr = std::unique_ptr<IPTables>;
}  // namespace fptn::routing
