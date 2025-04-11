/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <iostream>
#include <memory>
#include <mutex>
#include <string>

#if _WIN32
#pragma warning(disable : 4996)
#endif

#include <pcapplusplus/IpAddress.h>

#if _WIN32
#pragma warning(default : 4996)
#endif

namespace fptn::routing {
std::string GetDefaultNetworkInterfaceName() noexcept;
pcpp::IPv4Address GetDefaultGatewayIPAddress() noexcept;
pcpp::IPv4Address ResolveDomain(const std::string& domain) noexcept;

class IPTables final {
 public:
  IPTables(const std::string& out_interface_name,
      const std::string& tun_interface_name,
      const pcpp::IPv4Address& vpn_server_ip,
      const pcpp::IPv4Address& dns_server_ipv4,
      const pcpp::IPv6Address& dns_server_ipv6,
      const pcpp::IPv4Address& gateway_ip,
      const pcpp::IPv4Address& tun_interface_address_ipv4,
      const pcpp::IPv6Address& tun_interface_address_ipv6);
  ~IPTables();
  bool Check() noexcept;
  bool Apply() noexcept;
  bool Clean() noexcept;

 private:
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  const std::string out_interface_name_;
  const std::string tun_interface_name_;
  const pcpp::IPv4Address vpn_server_ip_;
  const pcpp::IPv4Address dns_server_ipv4_;
  const pcpp::IPv6Address dns_server_ipv6_;
  const pcpp::IPv4Address gateway_ip_;
  const pcpp::IPv4Address tun_interface_address_ipv4_;
  const pcpp::IPv6Address tun_interface_address_ipv6_;

 private:
  std::string detected_out_interface_name_;
  pcpp::IPv4Address find_out_gateway_ip_;
};

using IPTablesPtr = std::unique_ptr<IPTables>;
}  // namespace fptn::routing
