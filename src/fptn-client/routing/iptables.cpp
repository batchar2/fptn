/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "routing/iptables.h"

#include <string>
#include <vector>

#include "common/network/net_interface.h"
#include "common/system/command.h"

#ifdef _WIN32
static std::string GetWindowsInterfaceNumber(const std::string& interfaceName);
#endif

using fptn::routing::IPTables;

IPTables::IPTables(const std::string& out_interface_name,
    const std::string& tun_interface_name,
    const pcpp::IPv4Address& vpn_server_ip,
    const pcpp::IPv4Address& dns_server_ipv4,
    const pcpp::IPv6Address& dns_server_ipv6,
    const pcpp::IPv4Address& gateway_ip,
    const pcpp::IPv4Address& tun_interface_address_ipv4,
    const pcpp::IPv6Address& tun_interface_address_ipv6)
    : running_(false),
      out_interface_name_(out_interface_name),
      tun_interface_name_(tun_interface_name),
      vpn_server_ip_(vpn_server_ip),
      dns_server_ipv4_(dns_server_ipv4),
      dns_server_ipv6_(dns_server_ipv6),
      gateway_ip_(gateway_ip),
      tun_interface_address_ipv4_(tun_interface_address_ipv4),
      tun_interface_address_ipv6_(tun_interface_address_ipv6) {}

IPTables::~IPTables() {
  if (running_) {
    Clean();
  }
}

bool IPTables::Check() noexcept { return true; }

bool IPTables::Apply() noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);

  running_ = true;
#if defined(__APPLE__) || defined(__linux__)
  detected_out_interface_name_ =
      (out_interface_name_.empty() ? GetDefaultNetworkInterfaceName()
                                   : out_interface_name_);
#endif
  detected_gateway_ip_ = (gateway_ip_ == pcpp::IPv4Address("0.0.0.0")
                              ? GetDefaultGatewayIPAddress()
                              : gateway_ip_);

  SPDLOG_INFO("=== Setting up routing ===");
  SPDLOG_INFO("IPTABLES VPN SERVER IP:         {}", vpn_server_ip_.toString());
  SPDLOG_INFO(
      "IPTABLES OUT NETWORK INTERFACE: {}", detected_out_interface_name_);
  SPDLOG_INFO(
      "IPTABLES GATEWAY IP:            {}", detected_gateway_ip_.toString());
  SPDLOG_INFO(
      "IPTABLES DNS SERVER:            {}", dns_server_ipv4_.toString());
#ifdef __linux__
  const std::vector<std::string> commands = {
      fmt::format("systemctl start sysctl"),
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
          detected_out_interface_name_, vpn_server_ip_.toString()),
      fmt::format("iptables -A INPUT -i {} -s {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.toString()),
      // IPv4 default & DNS route
      fmt::format("ip route add default dev {}", tun_interface_name_),
      fmt::format("ip route add {} dev {}", dns_server_ipv4_.toString(),
          tun_interface_name_),  // via TUN
      // IPv6 default
      fmt::format("ip -6 route add default dev {}", tun_interface_name_),
      // exclude vpn server & networks
      fmt::format("ip route add {} via {} dev {}", vpn_server_ip_.toString(),
          detected_gateway_ip_.toString(), detected_out_interface_name_),
      fmt::format("ip route add 10.0.0.0/8 via {} dev {}",
          detected_gateway_ip_.toString(), detected_out_interface_name_),
      fmt::format("ip route add 172.16.0.0/12 via {} dev {}",
          detected_gateway_ip_.toString(), detected_out_interface_name_),
      fmt::format("ip route add 192.168.0.0/16 via {} dev {}",
          detected_gateway_ip_.toString(), detected_out_interface_name_),
      // DNS
      fmt::format("resolvectl dns {} {}", tun_interface_name_,
          dns_server_ipv4_.toString()),
      fmt::format("resolvectl domain {} \"~.\" ", tun_interface_name_),
      fmt::format("resolvectl default-route {} yes", tun_interface_name_)};
#elif __APPLE__
  const std::vector<std::string> commands = {
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")",
          dns_server_ipv4_.toString()),  // clean DNS
      fmt::format("sudo sysctl -w net.inet.ip.forwarding=1"),
      fmt::format(
          R"(sh -c "echo 'nat on {findOutInterfaceName} from {tunInterfaceName}:network to any -> ({findOutInterfaceName})
                pass out on {findOutInterfaceName} proto tcp from any to {vpnServerIP}
                pass in on {findOutInterfaceName} proto tcp from {vpnServerIP} to any
                pass in on {tunInterfaceName} proto tcp from any to any
                pass out on {tunInterfaceName} proto tcp from any to any' > /tmp/pf.conf"
            )",
          fmt::arg("findOutInterfaceName", detected_out_interface_name_),
          fmt::arg("tunInterfaceName", tun_interface_name_),
          fmt::arg("vpnServerIP", vpn_server_ip_.toString())),
      fmt::format("sudo pfctl -ef /tmp/pf.conf"),
      // default & DNS route
      fmt::format(
          "sudo route add -net 0.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "sudo route add -net 128.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format("sudo route add -host {} -interface {}",
          dns_server_ipv4_.toString(), tun_interface_name_),  // via TUN
      // exclude vpn server & networks
      fmt::format("sudo route add -host {} {}", vpn_server_ip_.toString(),
          detected_gateway_ip_.toString()),
      fmt::format(
          "sudo route add -net 10.0.0.0/8 {}", detected_gateway_ip_.toString()),
      fmt::format("sudo route add -net 172.16.0.0/12 {}",
          detected_gateway_ip_.toString()),
      fmt::format("sudo route add -net 192.168.0.0/16 {}",
          detected_gateway_ip_.toString()),
      // DNS
      fmt::format("sudo dscacheutil -flushcache"),
      fmt::format(
          R"(bash -c "sudo networksetup -listallnetworkservices | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' {}")",
          dns_server_ipv4_.toString())};
#elif _WIN32
  const std::string win_interface_number =
      GetWindowsInterfaceNumber(tun_interface_name_);
  const std::string interfaceInfo =
      win_interface_number.empty() ? "" : " if " + win_interface_number;
  const std::vector<std::string> commands = {
      fmt::format("netsh interface ip set dns name=\"{}\" dhcp",
          tun_interface_name_),  // CLEAN DNS
      fmt::format("route add {} mask 255.255.255.255 {} METRIC 2",
          vpn_server_ip_.toString(), detected_gateway_ip_.toString()),
      fmt::format("route add 10.0.0.0 mask 255.0.0.0 {} METRIC 2",
          detected_gateway_ip_.toString()),
      fmt::format("route add 172.16.0.0 mask 255.240.0.0 {} METRIC 2",
          detected_gateway_ip_.toString()),
      fmt::format("route add 192.168.0.0 mask 255.255.0.0 {} METRIC 2",
          detected_gateway_ip_.toString()),
      // Default gateway & dns
      fmt::format("route add 0.0.0.0 mask 0.0.0.0 {} METRIC 1 {}",
          tun_interface_address_ipv4_.toString(), interfaceInfo),
      fmt::format("route add {} mask 255.255.255.255 {} METRIC 2 {}",
          dns_server_ipv4_.toString(), tun_interface_address_ipv4_.toString(),
          interfaceInfo),  // via TUN
      // DNS
      fmt::format("netsh interface ip set dns name=\"{}\" static {}",
          tun_interface_name_, dns_server_ipv4_.toString()),
      // IPv6
      fmt::format("netsh interface ipv6 add route ::/0 \"{}\" \"{}\" ",
          tun_interface_name_, tun_interface_address_ipv6_.toString()),
      fmt::format("netsh interface ipv6 add dnsservers=\"{}\" \"{}\" index=1",
          tun_interface_name_, dns_server_ipv6_.toString())};
#else
#error "Unsupported system!"
#endif
  for (const auto& cmd : commands) {
    fptn::common::system::command::run(cmd);
  }
  SPDLOG_INFO("=== Routing setup completed successfully ===");
  return true;
}

bool IPTables::Clean() noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);

  if (!running_) {
    SPDLOG_INFO("No need to clean rules!");
    return true;
  }
#ifdef __linux__
  const std::vector<std::string> commands = {
      fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE",
          detected_out_interface_name_),
      fmt::format("iptables -D FORWARD -i {} -o {} -m state --state "
                  "RELATED,ESTABLISHED -j ACCEPT",
          detected_out_interface_name_, tun_interface_name_),
      fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT",
          tun_interface_name_, detected_out_interface_name_),
      fmt::format("iptables -D OUTPUT -o {} -d {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.toString()),
      fmt::format("iptables -D INPUT -i {} -s {} -j ACCEPT",
          detected_out_interface_name_, vpn_server_ip_.toString()),
      // del routes
      fmt::format("ip route del default dev {}", tun_interface_name_),
      fmt::format("ip route del {} via {} dev {}", vpn_server_ip_.toString(),
          detected_gateway_ip_.toString(), detected_out_interface_name_),
      fmt::format("ip route del 10.0.0.0/8 via {} dev {}",
          detected_gateway_ip_.toString(), detected_out_interface_name_),
      fmt::format("ip route del 172.16.0.0/12 via {} dev {}",
          detected_gateway_ip_.toString(), detected_out_interface_name_),
      fmt::format("ip route del 192.168.0.0/16 via {} dev {}",
          detected_gateway_ip_.toString(), detected_out_interface_name_),
      // DNS
      fmt::format("resolvectl dns {} '' ", tun_interface_name_),
      fmt::format("resolvectl domain {} '' ", detected_out_interface_name_),
      fmt::format(
          "resolvectl default-route {} no '' ", detected_out_interface_name_)};
#elif __APPLE__
  const std::vector<std::string> commands = {
      fmt::format(
          R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")"),  // clean DNS
      fmt::format("pfctl -F all -f /etc/pf.conf"),
      // del routes
      fmt::format("route delete -host {} -interface {}",
          dns_server_ipv4_.toString(), tun_interface_name_),  // via TUN
      fmt::format(
          "route delete -net 0.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format(
          "route delete -net 128.0.0.0/1 -interface {}", tun_interface_name_),
      fmt::format("route delete -host {} {}", vpn_server_ip_.toString(),
          detected_gateway_ip_.toString()),
      fmt::format(
          "route delete -net 10.0.0.0/8 {}", detected_gateway_ip_.toString()),
      fmt::format("route delete -net 172.16.0.0/12 {}",
          detected_gateway_ip_.toString()),
      fmt::format("route delete -net 192.168.0.0/16 {}",
          detected_gateway_ip_.toString()),
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
          vpn_server_ip_.toString(), detected_gateway_ip_.toString()),
      fmt::format("route delete 0.0.0.0 mask 0.0.0.0 {}",
          tun_interface_address_ipv4_.toString()),
      fmt::format("route delete 10.0.0.0 mask 255.0.0.0 {}",
          detected_gateway_ip_.toString()),
      fmt::format("route delete 172.16.0.0 mask 255.240.0.0 {}",
          detected_gateway_ip_.toString()),
      fmt::format("route delete 192.168.0.0 mask 255.255.0.0 {}",
          detected_gateway_ip_.toString()),
      // DNS
      fmt::format("netsh interface ip set dns name=\"{}\" dhcp",
          detected_out_interface_name_),
      fmt::format("route delete {} mask 255.255.255.255 {} METRIC 2 {}",
          dns_server_ipv4_.toString(), tun_interface_address_ipv4_.toString(),
          interface_info),  // via TUN
      // IPv6
      fmt::format("netsh interface ipv6 delete dnsservers \"{}\" {}",
          tun_interface_name_, dns_server_ipv6_.toString())};
#else
#error "Unsupported system!"
#endif
  for (const auto& cmd : commands) {
    fptn::common::system::command::run(cmd);
  }
  running_ = false;
  return true;
}

pcpp::IPv4Address fptn::routing::ResolveDomain(
    const std::string& domain) noexcept {
  try {
    try {
      // error test
      boost::asio::ip::make_address(domain);
      return domain;
    } catch (const std::exception&) {
      // Not a valid IP address, proceed with domain name resolution
    }
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints =
        resolver.resolve(domain, "");
    for (const auto& endpoint : endpoints) {
      return endpoint.endpoint().address().to_string();
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error resolving domain: {}", e.what());
  }
  return domain;
}

pcpp::IPv4Address fptn::routing::GetDefaultGatewayIPAddress() noexcept {
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
    std::vector<std::string> stdoutput;
    fptn::common::system::command::run(command, stdoutput);
    for (const auto& line : stdoutput) {
      std::string result = line;
      result.erase(std::remove_if(result.begin(), result.end(),
                       [](char c) { return !std::isdigit(c) && c != '.'; }),
          result.end());
      if (!result.empty() &&
          pcpp::IPv4Address(result) != pcpp::IPv4Address("0.0.0.0")) {
        return result;
      }
    }
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Error: Failed to retrieve the default gateway IP address. {}",
        ex.what());
  }
  return {};
}

std::string fptn::routing::GetDefaultNetworkInterfaceName() noexcept {
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
        R"(cmd.exe /c "FOR /F "tokens=1,2,3" %i IN ('route print ^| findstr /R /C:"0.0.0.0"') DO @echo %i")";
#endif
    std::vector<std::string> stdoutput;
    fptn::common::system::command::run(command, stdoutput);
    if (stdoutput.empty()) {
      spdlog::warn("Warning: Default gateway IP address not found.");
      return {};
    }
    for (const auto& line : stdoutput) {
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

#if _WIN32
static std::string GetWindowsInterfaceNumber(const std::string& interfaceName) {
  try {
    const std::string command =
        "powershell -Command \"(Get-NetAdapter -Name '" + interfaceName +
        "').ifIndex\"";
    std::vector<std::string> stdoutput;
    fptn::common::system::command::run(command, stdoutput);

    if (stdoutput.empty()) {
      spdlog::warn("Warning: Interface index not found.");
      return {};
    }
    for (const auto& line : stdoutput) {
      std::string result = line;
      result.erase(result.find_last_not_of(" \n\r\t") + 1);
      result.erase(0, result.find_first_not_of(" \n\r\t"));
      if (!result.empty() &&
          std::all_of(result.begin(), result.end(), ::isdigit)) {
        return result;
      }
    }
    SPDLOG_ERROR("Error: Invalid interface index format.");
    return {};
  } catch (const std::exception& ex) {
    SPDLOG_ERROR(
        "Error: failed to retrieve the interface index. Msg: {}", ex.what());
  }
  return {};
}
#endif
