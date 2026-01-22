/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "routing/route_manager.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "common/network/net_interface.h"
#include "common/system/command.h"

namespace {
#ifdef _WIN32

std::string GetWindowsInterfaceNumber(const std::string& interface_name) {
  if (interface_name.empty()) {
    return {};
  }

  ULONG out_buf_len = 0;
  PIP_ADAPTER_INFO adapter_info = nullptr;
  PIP_ADAPTER_INFO adapter = nullptr;

  DWORD dw_ret = GetAdaptersInfo(nullptr, &out_buf_len);
  if (dw_ret != ERROR_BUFFER_OVERFLOW) {
    return {};
  }

  adapter_info = static_cast<PIP_ADAPTER_INFO>(malloc(out_buf_len));
  if (!adapter_info) {
    return {};
  }

  dw_ret = GetAdaptersInfo(adapter_info, &out_buf_len);
  if (dw_ret != NO_ERROR) {
    free(adapter_info);
    return {};
  }

  DWORD if_index = 0;
  adapter = adapter_info;

  while (adapter) {
    std::string adapter_name = adapter->AdapterName;
    std::string description = adapter->Description;

    if (interface_name == adapter_name || interface_name == description) {
      if_index = adapter->Index;
      break;
    }
    adapter = adapter->Next;
  }
  free(adapter_info);
  return if_index > 0 ? std::to_string(if_index) : std::string();
}

std::pair<std::string, std::string> ParseIPv4CIDR(const std::string& network) {
  std::string ip = network;
  std::string mask = "255.255.255.255";

  std::size_t slash_pos = network.find('/');
  if (slash_pos != std::string::npos) {
    ip = network.substr(0, slash_pos);
    std::string cidr_str = network.substr(slash_pos + 1);

    try {
      int cidr = std::stoi(cidr_str);
      if (cidr >= 0 && cidr <= 32) {
        std::uint32_t mask_value = 0;
        if (cidr > 0) {
          mask_value = ~0u << (32 - cidr);
        }
        mask = fmt::format("{}.{}.{}.{}", (mask_value >> 24) & 0xFF,
            (mask_value >> 16) & 0xFF, (mask_value >> 8) & 0xFF,
            mask_value & 0xFF);
      }
    } catch (...) {
      SPDLOG_WARN("Warning: Failed to parse CIDR: {}", network);
    }
  }
  return {ip, mask};
}

std::pair<std::string, int> ParseIPv6CIDR(const std::string& network) {
  std::string ip = network;
  int prefix = 128;

  size_t slash_pos = network.find('/');
  if (slash_pos != std::string::npos) {
    ip = network.substr(0, slash_pos);
    std::string cidr_str = network.substr(slash_pos + 1);

    try {
      int cidr = std::stoi(cidr_str);
      if (cidr >= 0 && cidr <= 128) {
        prefix = cidr;
      }
    } catch (...) {
      SPDLOG_WARN("Warning: Failed to parse IPv6 CIDR: {}", network);
    }
  }
  return {ip, prefix};
}

#endif

bool AddIPv4RouteToSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format("ip route add {} via {} dev {}",
        destination, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route add -net {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, mask] = ParseIPv4CIDR(destination);
    std::string interface_param = "";
    if (!out_interface.empty()) {
      std::string interface_number = GetWindowsInterfaceNumber(out_interface);
      if (!interface_number.empty()) {
        interface_param = "if " + interface_number;
      }
    }
    const std::string command =
        fmt::format("route add {} mask {} {} METRIC 2 {}", ip, mask, gateway_ip,
            interface_param);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to add IPv4 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error adding IPv4 route: {}", destination);
    return false;
  }
}

bool AddIPv6RouteToSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format("ip -6 route add {} via {} dev {}",
        destination, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route add -inet6 {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, prefix] = ParseIPv6CIDR(destination);
    std::string interface_name = out_interface;
    if (interface_name.empty()) {
      SPDLOG_ERROR("Interface name required for IPv6 route on Windows");
      return false;
    }
    const std::string command =
        fmt::format("netsh interface ipv6 add route {}/{} \"{}\" {}", ip,
            prefix, interface_name, gateway_ip);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to add IPv6 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error adding IPv6 route: {}", destination);
    return false;
  }
}

bool RemoveIPv4RouteFromSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format("ip route del {} via {} dev {}",
        destination, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route delete -net {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, mask] = ParseIPv4CIDR(destination);
    std::string interface_param = "";
    if (!out_interface.empty()) {
      std::string interface_number = GetWindowsInterfaceNumber(out_interface);
      if (!interface_number.empty()) {
        interface_param = "if " + interface_number;
      }
    }
    const std::string command = fmt::format(
        "route delete {} mask {} {} {}", ip, mask, gateway_ip, interface_param);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to remove IPv4 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error removing IPv4 route: {}", destination);
    return false;
  }
}

bool RemoveIPv6RouteFromSystem(const std::string& destination,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format("ip -6 route del {} via {} dev {}",
        destination, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route delete -inet6 {} {}", destination, gateway_ip);
#elif _WIN32
    auto [ip, prefix] = ParseIPv6CIDR(destination);
    std::string interface_name = out_interface;
    if (interface_name.empty()) {
      SPDLOG_ERROR("Interface name required for IPv6 route removal on Windows");
      return false;
    }
    const std::string command =
        fmt::format("netsh interface ipv6 delete route {}/{} \"{}\"", ip,
            prefix, interface_name);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to remove IPv6 route {}: {}", destination, e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown error removing IPv6 route: {}", destination);
    return false;
  }
}

}  // namespace

using fptn::routing::RouteManager;

RouteManager::RouteManager(std::string out_interface_name,
    std::string tun_interface_name,
    fptn::common::network::IPv4Address vpn_server_ip,
    fptn::common::network::IPv4Address dns_server_ipv4,
    fptn::common::network::IPv6Address dns_server_ipv6,
    fptn::common::network::IPv4Address gateway_ipv4,
    fptn::common::network::IPv6Address gateway_ipv6,
    fptn::common::network::IPv4Address tun_interface_address_ipv4,
    fptn::common::network::IPv6Address tun_interface_address_ipv6)
    : running_(false),
      out_interface_name_(std::move(out_interface_name)),
      tun_interface_name_(std::move(tun_interface_name)),
      vpn_server_ip_(std::move(vpn_server_ip)),
      dns_server_ipv4_(std::move(dns_server_ipv4)),
      dns_server_ipv6_(std::move(dns_server_ipv6)),
      gateway_ipv4_(std::move(gateway_ipv4)),
      gateway_ipv6_(std::move(gateway_ipv6)),
      tun_interface_address_ipv4_(std::move(tun_interface_address_ipv4)),
      tun_interface_address_ipv6_(std::move(tun_interface_address_ipv6)) {}

RouteManager::~RouteManager() {  // NOLINT(bugprone-exception-escape)
  if (running_) {
    Clean();
  }
}

bool RouteManager::Apply() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  running_ = true;
#if defined(__APPLE__) || defined(__linux__)
  detected_out_interface_name_ =
      (out_interface_name_.empty() ? GetDefaultNetworkInterfaceName()
                                   : out_interface_name_);
#endif
  detected_out_interface_name_ =
      (out_interface_name_.empty() ? GetDefaultNetworkInterfaceName()
                                   : out_interface_name_);
  detected_gateway_ipv4_ =
      gateway_ipv4_.IsEmpty() ? GetDefaultGatewayIPAddress() : gateway_ipv4_;

  SPDLOG_INFO("=== Setting up routing ===");
  SPDLOG_INFO("IPTABLES VPN SERVER IP:         {}", vpn_server_ip_.ToString());
  SPDLOG_INFO(
      "IPTABLES OUT NETWORK INTERFACE: {}", detected_out_interface_name_);
  SPDLOG_INFO(
      "IPTABLES GATEWAY IP:            {}", detected_gateway_ipv4_.ToString());
  SPDLOG_INFO(
      "IPTABLES DNS SERVER:            {}", dns_server_ipv4_.ToString());
#ifdef __linux__
  std::vector<std::string> commands = {fmt::format("systemctl start sysctl"),
      fmt::format("sysctl -w net.ipv4.ip_forward=1"),
      fmt::format("sysctl -w net.ipv6.conf.default.disable_ipv6=0"),
      fmt::format("sysctl -w net.ipv6.conf.all.disable_ipv6=0"),
      fmt::format("sysctl -w net.ipv6.conf.lo.disable_ipv6=0"),
      fmt::format("sysctl -w net.ipv6.conf.all.forward=1"),
      fmt::format("sysctl -p"),
      // iptables
      fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE",
          detected_out_interface_name_),
      fmt::format("iptables -A FORWARD -i {} -o {} -m state --state "
                  "RELATED,ESTABLISHED -j ACCEPT",
          detected_out_interface_name_, tun_interface_name_),
      fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT",
          tun_interface_name_, detected_out_interface_name_),
      fmt::format("iptables -A OUTPUT -o {} -d {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.ToString()),
      fmt::format("iptables -A INPUT -i {} -s {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.ToString()),
      // IPv4 default & DNS route
      fmt::format("ip route add default dev {}", tun_interface_name_),
      fmt::format("ip route add {} dev {}", dns_server_ipv4_.ToString(),
          tun_interface_name_),  // via TUN
      // IPv6 default
      fmt::format("ip -6 route add default dev {}", tun_interface_name_),
      // exclude vpn server
      fmt::format("ip route add {} via {} dev {}", vpn_server_ip_.ToString(),
          detected_gateway_ipv4_.ToString(), detected_out_interface_name_)};

  commands.push_back(
      fmt::format("resolvectl dns {} ''", detected_out_interface_name_));
  commands.push_back(fmt::format(
      "resolvectl default-route {} true", detected_out_interface_name_));
  commands.push_back(fmt::format("resolvectl dns {} ''", tun_interface_name_));
  commands.push_back(
      fmt::format("resolvectl domain {} ''", tun_interface_name_));
  commands.push_back(
      fmt::format("resolvectl default-route {} false", tun_interface_name_));
  commands.push_back(fmt::format("resolvectl flush-caches"));

#elif __APPLE__
  const std::vector<std::string> commands = {
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")",
          dns_server_ipv4_.ToString()),  // clean DNS
      fmt::format("sysctl -w net.inet.ip.forwarding=1"),
      fmt::format(
          R"(sh -c "echo 'nat on {findOutInterfaceName} from {tunInterfaceName}:network to any -> ({findOutInterfaceName})
                pass out on {findOutInterfaceName} proto tcp from any to {vpnServerIP}
                pass in on {findOutInterfaceName} proto tcp from {vpnServerIP} to any
                pass in on {tunInterfaceName} proto tcp from any to any
                pass out on {tunInterfaceName} proto tcp from any to any' > /tmp/pf.conf"
            )",
          fmt::arg("findOutInterfaceName", detected_out_interface_name_),
          fmt::arg("tunInterfaceName", tun_interface_name_),
          fmt::arg("vpnServerIP", vpn_server_ip_.ToString())),
      fmt::format("pfctl -ef /tmp/pf.conf"),
      // default & DNS route
      fmt::format(
          "route add -net 0.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "route add -net 128.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format("route add -host {} -interface {}",
          dns_server_ipv4_.ToString(), tun_interface_name_),  // via TUN
      // exclude vpn server & networks
      fmt::format("route add -host {} {}", vpn_server_ip_.ToString(),
          detected_gateway_ipv4_.ToString()),
      // DNS
      fmt::format("dscacheutil -flushcache"),
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' {}")",
          dns_server_ipv4_.ToString())};
#elif _WIN32
  const std::string win_interface_number =
      GetWindowsInterfaceNumber(tun_interface_name_);
  const std::string interfaceInfo =
      win_interface_number.empty() ? "" : " if " + win_interface_number;
  const std::vector<std::string> commands = {
      fmt::format("netsh interface ip set dns name=\"{}\" dhcp",
          tun_interface_name_),  // CLEAN DNS
      fmt::format("route add {} mask 255.255.255.255 {} METRIC 2",
          vpn_server_ip_.ToString(), detected_gateway_ipv4_.ToString()),
      // Default gateway & dns
      fmt::format("route add 0.0.0.0 mask 0.0.0.0 {} METRIC 1 {}",
          tun_interface_address_ipv4_.ToString(), interfaceInfo),
      fmt::format("route add {} mask 255.255.255.255 {} METRIC 2 {}",
          dns_server_ipv4_.ToString(), tun_interface_address_ipv4_.ToString(),
          interfaceInfo),  // via TUN
      // DNS
      fmt::format("netsh interface ip set dns name=\"{}\" static {}",
          tun_interface_name_, dns_server_ipv4_.ToString()),
      // IPv6
      fmt::format("netsh interface ipv6 add route ::/0 \"{}\" \"{}\" ",
          tun_interface_name_, tun_interface_address_ipv6_.ToString()),
      fmt::format("netsh interface ipv6 add dnsservers=\"{}\" \"{}\" index=1",
          tun_interface_name_, dns_server_ipv6_.ToString())};
#else
#error "Unsupported system!"
#endif
  try {
    for (const auto& cmd : commands) {
      fptn::common::system::command::run(cmd);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IPTables error: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined error");
  }
  SPDLOG_INFO("=== Routing setup completed successfully ===");
  return true;
}

bool RouteManager::Clean() {  // NOLINT(bugprone-exception-escape)
  if (!running_) {
    SPDLOG_INFO("No need to clean rules!");
    return true;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  running_ = false;

  // clean dns ipv4
  for (const auto& ip : dns_routes_ipv4_) {
    std::string interface_name;
    if (ip.policy == RoutingPolicy::kExcludeFromVpn) {
      if (!detected_out_interface_name_.empty()) {
        interface_name = detected_out_interface_name_;
      } else if (!out_interface_name_.empty()) {
        interface_name = out_interface_name_;
      } else {
        interface_name = GetDefaultNetworkInterfaceName();
      }
    } else {
      interface_name = tun_interface_name_;
    }
    RemoveIPv4RouteFromSystem(
        ip.destination, gateway_ipv4_.ToString(), interface_name);
  }
  dns_routes_ipv4_.clear();

  // clean dns ipv6
  for (const auto& ip : dns_routes_ipv6_) {
    std::string interface_name;
    if (ip.policy == RoutingPolicy::kExcludeFromVpn) {
      if (!detected_out_interface_name_.empty()) {
        interface_name = detected_out_interface_name_;
      } else if (!out_interface_name_.empty()) {
        interface_name = out_interface_name_;
      } else {
        interface_name = GetDefaultNetworkInterfaceName();
      }
    } else {
      interface_name = tun_interface_name_;
    }
    RemoveIPv6RouteFromSystem(
        ip.destination, gateway_ipv6_.ToString(), interface_name);
  }
  dns_routes_ipv6_.clear();

  // clean route ipv4
  for (const auto& route : additional_routes_ipv4_) {
    if (route.policy == RoutingPolicy::kExcludeFromVpn) {
      RemoveIPv4RouteFromSystem(
          route.destination, gateway_ipv4_.ToString(), out_interface_name_);
    } else {
      // Include route - remove through VPN interface
      RemoveIPv4RouteFromSystem(route.destination,
          tun_interface_address_ipv4_.ToString(), tun_interface_name_);
    }
  }
  additional_routes_ipv4_.clear();

  // Remove additional IPv6 routes
  for (const auto& route : additional_routes_ipv6_) {
    if (route.policy == RoutingPolicy::kExcludeFromVpn) {
      RemoveIPv6RouteFromSystem(
          route.destination, gateway_ipv6_.ToString(), out_interface_name_);
    } else {
      // Include route - remove through VPN interface
      RemoveIPv6RouteFromSystem(route.destination,
          tun_interface_address_ipv6_.ToString(), tun_interface_name_);
    }
  }
  additional_routes_ipv6_.clear();

#ifdef __linux__
  std::vector<std::string> commands = {
      fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE",
          detected_out_interface_name_),
      fmt::format("iptables -D FORWARD -i {} -o {} -m state --state "
                  "RELATED,ESTABLISHED -j ACCEPT",
          detected_out_interface_name_, tun_interface_name_),
      fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT",
          tun_interface_name_, detected_out_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -d {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.ToString()),
      fmt::format("iptables -D INPUT -i {} -s {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.ToString()),
      // del routes
      fmt::format("ip route del default dev {}", tun_interface_name_),
      fmt::format("ip route del {} via {} dev {}", vpn_server_ip_.ToString(),
          detected_gateway_ipv4_.ToString(), detected_out_interface_name_)};
  // DNS
  commands.push_back(
      fmt::format("resolvectl dns {} ''", detected_out_interface_name_));
  commands.push_back(fmt::format(
      "resolvectl default-route {} true", detected_out_interface_name_));
  commands.push_back(fmt::format("resolvectl dns {} ''", tun_interface_name_));
  commands.push_back(
      fmt::format("resolvectl domain {} ''", tun_interface_name_));
  commands.push_back(
      fmt::format("resolvectl default-route {} false", tun_interface_name_));
  commands.push_back(fmt::format("resolvectl flush-caches"));

#elif __APPLE__
  const std::vector<std::string> commands = {
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")"),  // clean DNS
      fmt::format("pfctl -F all -f /etc/pf.conf"),
      // del routes
      fmt::format("route delete -host {} -interface {}",
          dns_server_ipv4_.ToString(),
          tun_interface_name_),  // via TUN
      fmt::format(
          "route delete -net 0.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "route delete -net 128.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format("route delete -host {} {}", vpn_server_ip_.ToString(),
          detected_gateway_ipv4_.ToString()),
      // DNS
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")")  // clean DNS
  };
#elif _WIN32
  const std::string win_interface_number =
      GetWindowsInterfaceNumber(tun_interface_name_);
  const std::string interface_info =
      win_interface_number.empty() ? "" : " if " + win_interface_number;
  const std::vector<std::string> commands = {
      fmt::format("route delete {} mask 255.255.255.255 {}",
          vpn_server_ip_.ToString(), detected_gateway_ipv4_.ToString()),
      fmt::format("route delete 0.0.0.0 mask 0.0.0.0 {}",
          tun_interface_address_ipv4_.ToString()),
      // DNS
      fmt::format(
          "netsh interface ip set dns name=\"{}\" dhcp", tun_interface_name_),
      fmt::format("route delete {} mask 255.255.255.255 {} METRIC 2 {}",
          dns_server_ipv4_.ToString(), tun_interface_address_ipv4_.ToString(),
          interface_info),  // via TUN
      // IPv6
      fmt::format("netsh interface ipv6 delete dnsservers \"{}\" {}",
          tun_interface_name_, dns_server_ipv6_.ToString())};
#else
#error "Unsupported system!"
#endif
  try {
    for (const auto& cmd : commands) {
      fptn::common::system::command::run(cmd);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IPTables error: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined error");
  }
  running_ = false;
  return true;
}

bool RouteManager::AddDnsRoutesIPv4(
    const std::vector<fptn::common::network::IPv4Address>& ips,
    const RoutingPolicy policy) {
  std::string interface_name;
  std::string gateway_ip;

  if (policy == RoutingPolicy::kExcludeFromVpn) {
    if (!detected_out_interface_name_.empty()) {
      interface_name = detected_out_interface_name_;
    } else if (!out_interface_name_.empty()) {
      interface_name = out_interface_name_;
    } else {
      interface_name = GetDefaultNetworkInterfaceName();
    }
    gateway_ip = gateway_ipv4_.ToString();
  } else {
    interface_name = tun_interface_name_;
    gateway_ip = tun_interface_address_ipv4_.ToString();
  }

  if (interface_name.empty()) {
    SPDLOG_WARN(
        "Cannot add DNS IPv4 routes: interface name is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  std::vector<RouteEntry> entries_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& ip : ips) {
      std::string ip_str = ip.ToString();
      RouteEntry entry{.destination = ip_str, .policy = policy};

      if (!dns_routes_ipv4_.contains(entry)) {
        dns_routes_ipv4_.insert(entry);
        entries_to_add.push_back(std::move(entry));
      }
    }
  }

  if (entries_to_add.empty()) {
    return true;
  }

  bool status = true;
  for (const auto& entry : entries_to_add) {
    try {
      const bool rv =
          AddIPv4RouteToSystem(entry.destination, gateway_ip, interface_name);

      if (rv) {
        const std::string policy_str = (policy == RoutingPolicy::kExcludeFromVpn
                                            ? "EXCLUDE (bypass VPN)"
                                            : "INCLUDE (through VPN)");
        SPDLOG_INFO("DNS route added: {} [{}]", entry.destination, policy_str);
      } else {
        SPDLOG_WARN("Failed to add DNS route: {}", entry.destination);

        const std::unique_lock<std::mutex> lock(mutex_);
        dns_routes_ipv4_.erase(entry);
        status = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Exception adding DNS IPv4 route {}: {}", entry.destination,
          e.what());

      const std::unique_lock<std::mutex> lock(mutex_);
      dns_routes_ipv4_.erase(entry);
      status = false;
    }
  }

  return status;
}

bool RouteManager::AddDnsRoutesIPv6(
    const std::vector<fptn::common::network::IPv6Address>& ips,
    const RoutingPolicy policy) {
  std::string interface_name;
  std::string gateway_ip;

  if (policy == RoutingPolicy::kExcludeFromVpn) {
    if (!detected_out_interface_name_.empty()) {
      interface_name = detected_out_interface_name_;
    } else if (!out_interface_name_.empty()) {
      interface_name = out_interface_name_;
    } else {
      interface_name = GetDefaultNetworkInterfaceName();
    }
    gateway_ip = gateway_ipv6_.ToString();
  } else {
    interface_name = tun_interface_name_;
    gateway_ip = tun_interface_address_ipv6_.ToString();
  }

  if (interface_name.empty()) {
    SPDLOG_WARN(
        "Cannot add DNS IPv6 routes: interface name is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  if (gateway_ip.empty()) {
    SPDLOG_WARN("Cannot add DNS IPv6 routes: gateway IP is empty for policy {}",
        policy == RoutingPolicy::kExcludeFromVpn ? "EXCLUDE" : "INCLUDE");
    return false;
  }

  std::vector<RouteEntry> entries_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& ip : ips) {
      std::string ip_str = ip.ToString();
      RouteEntry entry{.destination = ip_str, .policy = policy};

      if (!dns_routes_ipv6_.contains(entry)) {
        dns_routes_ipv6_.insert(entry);
        entries_to_add.push_back(std::move(entry));
      }
    }
  }

  if (entries_to_add.empty()) {
    return true;
  }

  bool status = true;
  for (const auto& entry : entries_to_add) {
    try {
      const bool rv =
          AddIPv6RouteToSystem(entry.destination, gateway_ip, interface_name);

      if (rv) {
        const std::string policy_str = (policy == RoutingPolicy::kExcludeFromVpn
                                            ? "EXCLUDE (bypass VPN)"
                                            : "INCLUDE (through VPN)");
        SPDLOG_INFO(
            "DNS IPv6 route added: {} [{}]", entry.destination, policy_str);
      } else {
        SPDLOG_WARN("Failed to add DNS IPv6 route: {}", entry.destination);
        status = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Exception adding DNS IPv6 route {}: {}", entry.destination,
          e.what());
      status = false;
    }
  }
  return status;
}

bool RouteManager::AddExcludeNetworks(
    const std::vector<std::string>& networks) {
  std::vector<std::pair<std::string, bool>> networks_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& network : networks) {
      if (network.empty()) {
        continue;
      }

      const bool is_ipv6 = network.find(':') != std::string::npos;  // NOLINT
      RouteEntry entry{
          .destination = network, .policy = RoutingPolicy::kExcludeFromVpn};

      if (is_ipv6) {
        if (!additional_routes_ipv6_.contains(entry)) {
          networks_to_add.emplace_back(network, true);
          additional_routes_ipv6_.insert(entry);
        }
      } else {
        if (!additional_routes_ipv4_.contains(entry)) {
          networks_to_add.emplace_back(network, false);
          additional_routes_ipv4_.insert(entry);
        }
      }
    }
    if (networks_to_add.empty()) {
      return true;
    }
  }

  bool all_success = true;
  for (const auto& [network, is_ipv6] : networks_to_add) {
    try {
      bool success = false;

      if (is_ipv6) {
#ifdef _WIN32
        std::string interface_name = !detected_out_interface_name_.empty()
                                         ? detected_out_interface_name_
                                         : out_interface_name_;
#else
        std::string interface_name = out_interface_name_;
#endif
        success = AddIPv6RouteToSystem(
            network, gateway_ipv6_.ToString(), interface_name);
      } else {
        success = AddIPv4RouteToSystem(
            network, gateway_ipv4_.ToString(), out_interface_name_);
      }

      if (success) {
        SPDLOG_INFO(
            "Added {} exclude network: {}", is_ipv6 ? "IPv6" : "IPv4", network);
      } else {
        SPDLOG_WARN("Failed to add route: {}", network);
        all_success = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Failed to add exclude network '{}': {}", network, e.what());

      const std::unique_lock<std::mutex> lock(mutex_);
      RouteEntry entry{
          .destination = network, .policy = RoutingPolicy::kExcludeFromVpn};
      if (is_ipv6) {
        additional_routes_ipv6_.erase(entry);
      } else {
        additional_routes_ipv4_.erase(entry);
      }
      all_success = false;
    }
  }
  return all_success;
}

bool RouteManager::AddIncludeNetworks(
    const std::vector<std::string>& networks) {
  std::vector<std::pair<std::string, bool>> networks_to_add;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    for (const auto& network : networks) {
      if (network.empty()) {
        continue;
      }

      const bool is_ipv6 = network.find(':') != std::string::npos;  // NOLINT
      RouteEntry entry{
          .destination = network, .policy = RoutingPolicy::kIncludeInVpn};

      if (is_ipv6) {
        if (!additional_routes_ipv6_.contains(entry)) {
          networks_to_add.emplace_back(network, true);
          additional_routes_ipv6_.insert(entry);
        }
      } else {
        if (!additional_routes_ipv4_.contains(entry)) {
          networks_to_add.emplace_back(network, false);
          additional_routes_ipv4_.insert(entry);
        }
      }
    }
    if (networks_to_add.empty()) {
      return true;
    }
  }

  bool all_success = true;
  for (const auto& [network, is_ipv6] : networks_to_add) {
    try {
      bool success = false;

      if (is_ipv6) {
        success = AddIPv6RouteToSystem(network,
            tun_interface_address_ipv6_.ToString(), tun_interface_name_);
      } else {
        success = AddIPv4RouteToSystem(network,
            tun_interface_address_ipv4_.ToString(), tun_interface_name_);
      }

      if (success) {
        SPDLOG_INFO(
            "Added {} include network: {}", is_ipv6 ? "IPv6" : "IPv4", network);
      } else {
        SPDLOG_ERROR("Failed to add route: {}", network);
        all_success = false;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Failed to add include network '{}': {}", network, e.what());
      all_success = false;
    }
  }

  return all_success;
}

// NOLINT(bugprone-exception-escape)
fptn::common::network::IPv4Address fptn::routing::ResolveDomain(
    const std::string& domain) {
  try {
    try {
      // error test
      boost::asio::ip::make_address(domain);
      return fptn::common::network::IPv4Address::Create(domain);
    } catch (const std::exception&) {  // NOLINT(bugprone-empty-catch)
      // Not a valid IP address, proceed with domain name resolution
    }
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints =
        resolver.resolve(domain, "");
    for (const auto& endpoint : endpoints) {
      return fptn::common::network::IPv4Address(
          endpoint.endpoint().address().to_string());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error resolving domain: {}", e.what());
  }
  return fptn::common::network::IPv4Address(domain);
}

fptn::common::network::IPv4Address fptn::routing::GetDefaultGatewayIPAddress() {
  try {
#ifdef __linux__
    const std::string command = "ip route get 8.8.8.8 | awk '{print $3; exit}'";
#elif __APPLE__
    const std::string command =
        "route get 8.8.8.8 | grep gateway | awk '{print $2}' ";
#elif _WIN32
    const std::string command =
        R"(cmd.exe /c FOR /f "tokens=3" %i in ('route print ^| find "0.0.0.0"') do @echo %i)";
#else
#error "Unsupported system!"
#endif
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(command, cmd_stdout);
    for (const auto& line : cmd_stdout) {
      std::string result = line;
      result.erase(
          // NOLINTNEXTLINE(modernize-use-ranges)
          std::remove_if(result.begin(), result.end(),
              [](char c) {
                /* Allow: a-z, A-Z, 0-9, dot, dash */
                return !std::isalnum(c) && c != '.' && c != '-' && c != '_';
              }),
          result.end());
      if (!result.empty()) {
        return ResolveDomain(result);
      }
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error: Failed to retrieve the default gateway IP address. {}",
        ex.what());
  }
  return {};
}

fptn::common::network::IPv6Address
fptn::routing::GetDefaultGatewayIPv6Address() {
  try {
#ifdef __linux__
    const std::string command =
        "ip -6 route | grep default | head -1 | awk '{print $3}'";
#elif __APPLE__
    const std::string command =
        "route -6 get default | grep gateway | awk '{print $2}'";
#elif _WIN32
    const std::string command =
        R"(netsh interface ipv6 show routes | find "::/0" | head -1 | awk "{print $3}")";
#else
    return {};
#endif
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(command, cmd_stdout);

    for (const auto& line : cmd_stdout) {
      std::string result = line;
      std::erase_if(result, [](const char c) {
        return !std::isalnum(c) && c != ':' && c != '.' && c != '-';
      });
      if (!result.empty()) {
        return fptn::common::network::IPv6Address::Create(result);
      }
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error getting IPv6 gateway: {}", ex.what());
  }
  return {};
}

std::string fptn::routing::GetDefaultNetworkInterfaceName() {
  std::string result;
  try {
#ifdef __linux__
    const std::string command =
        "ip route get 8.8.8.8 | awk '{print $5; exit}' ";
#elif __APPLE__
    const std::string command =
        "route get 8.8.8.8 | grep interface | awk '{print $2}' ";
#elif _WIN32
    const std::string command =
        R"(powershell -Command "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Select-Object -First 1).InterfaceAlias")";
#endif
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(command, cmd_stdout);
    if (cmd_stdout.empty()) {
      SPDLOG_WARN("Warning: Default gateway IP address not found.");
      return {};
    }
    for (const auto& line : cmd_stdout) {
      result = line;
      result.erase(result.find_last_not_of(" \n\r\t") + 1);
      result.erase(0, result.find_first_not_of(" \n\r\t"));
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error: Failed to retrieve the default gateway IP address. {}",
        ex.what());
  }
  return result;
}
