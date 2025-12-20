/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "split/route/route_manager.h"

#include <string>
#include <utility>
#include <vector>

#include <fmt/base.h>       // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/system/command.h"

namespace {

bool AddIPv4RouteToSystem(const std::string& ip,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format(
        "ip route add {} via {} dev {}", ip, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route add -host {} {}", ip, gateway_ip);
#elif _WIN32
    const std::string command = fmt::format(
        "route add {} mask 255.255.255.255 {} METRIC 2", ip, gateway_ip);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to add IPv4 route {}: {}", ip, e.what());
    return false;
  }
}

bool AddIPv6RouteToSystem(const std::string& ip,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format(
        "ip -6 route add {} via {} dev {}", ip, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route add -inet6 {} {}", ip, gateway_ip);
#elif _WIN32
    const std::string command =
        fmt::format("netsh interface ipv6 add route {}/128 {}", ip, gateway_ip);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to add IPv6 route {}: {}", ip, e.what());
    return false;
  }
}

bool RemoveIPv4RouteFromSystem(const std::string& ip,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format(
        "ip route del {} via {} dev {}", ip, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route delete -host {} {}", ip, gateway_ip);
#elif _WIN32
    const std::string command = fmt::format("route delete {}", ip);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to remove IPv4 route {}: {}", ip, e.what());
    return false;
  }
}

bool RemoveIPv6RouteFromSystem(const std::string& ip,
    const std::string& gateway_ip,
    const std::string& out_interface) {
  (void)gateway_ip;
  (void)out_interface;
  try {
#ifdef __linux__
    const std::string command = fmt::format(
        "ip -6 route del {} via {} dev {}", ip, gateway_ip, out_interface);
#elif __APPLE__
    const std::string command =
        fmt::format("route delete -inet6 {} {}", ip, gateway_ip);
#elif _WIN32
    const std::string command = fmt::format(
        "netsh interface ipv6 delete route {}/128 {}", ip, gateway_ip);
#else
    return false;
#endif
    fptn::common::system::command::run(command);
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Failed to remove IPv6 route {}: {}", ip, e.what());
    return false;
  }
}
}  // namespace

namespace fptn::split {

RouteManager::RouteManager(std::string out_interface_name,
    fptn::common::network::IPv4Address gateway_ipv4)
    : out_interface_name_(std::move(out_interface_name)),
      gateway_ipv4_(std::move(gateway_ipv4)) {
  /* ,gateway_ipv6_(std::move(gateway_ipv6)) */
  /*,fptn::common::network::IPv6Address gateway_ipv6*/
}

RouteManager::~RouteManager() { ClearRoutes(); }

bool RouteManager::AddRoutesIPv4(
    const std::vector<fptn::common::network::IPv4Address>& ips) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  bool status = true;
  for (const auto& ip : ips) {
    std::string ip_str = ip.ToString();
    if (!added_routes_ipv4.contains(ip_str)) {
      const bool rv = AddIPv4RouteToSystem(
          ip_str, gateway_ipv4_.ToString(), out_interface_name_);
      if (rv) {
        added_routes_ipv4.insert(std::move(ip_str));
      } else {
        status = false;
      }
    }
  }
  return status;
}

bool RouteManager::AddRoutesIPv6(
    const std::vector<fptn::common::network::IPv6Address>& ips) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  bool status = true;
  for (const auto& ip : ips) {
    std::string ip_str = ip.ToString();
    if (!added_routes_ipv6.contains(ip_str)) {
      const bool rv = AddIPv6RouteToSystem(
          ip_str, gateway_ipv6_.ToString(), out_interface_name_);
      if (rv) {
        added_routes_ipv6.insert(std::move(ip_str));
      } else {
        status = false;
      }
    }
  }
  return status;
}

void RouteManager::ClearRoutes() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  for (const auto& ip : added_routes_ipv4) {
    RemoveIPv4RouteFromSystem(
        ip, gateway_ipv4_.ToString(), out_interface_name_);
  }

  for (const auto& ip : added_routes_ipv6) {
    RemoveIPv6RouteFromSystem(
        ip, gateway_ipv6_.ToString(), out_interface_name_);
  }
  added_routes_ipv4.clear();
  added_routes_ipv6.clear();
}

}  // namespace fptn::split
