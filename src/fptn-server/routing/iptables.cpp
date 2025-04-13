/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "routing/iptables.h"

#include <string>
#include <utility>
#include <vector>

#include <boost/process.hpp>
#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

using fptn::routing::IPTables;

namespace {
bool RunCommand(const std::string& command) noexcept {
  try {
    boost::process::child child(command, boost::process::std_out > stdout,
        boost::process::std_err > stderr);
    child.wait();
    if (child.exit_code() == 0) {
      return true;
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IPTables error: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined error");
  }
  return false;
}

}  // namespace

IPTables::IPTables(
    std::string out_net_interface_name, std::string tun_net_interface_name)
    : out_net_interface_name_(std::move(out_net_interface_name)),
      tun_net_interface_name_(std::move(tun_net_interface_name)),
      running_(false) {}

IPTables::~IPTables() {
  try {
    Clean();
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Exception in IPTables destructor: {}", ex.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown error in IPTables destructor");
  }
}

bool IPTables::Apply() {  // NOLINT(bugprone-exception-escape)
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  running_ = true;
#ifdef __linux__
  const std::vector<std::string> commands = {"systemctl start sysctl",
      "sysctl -w net.ipv4.ip_forward=1",
      "sysctl -w net.ipv4.conf.all.rp_filter=0",
      "sysctl -w net.ipv4.conf.default.rp_filter=0",
      "sysctl -w net.ipv6.conf.default.disable_ipv6=0",
      "sysctl -w net.ipv6.conf.all.disable_ipv6=0",
      "sysctl -w net.ipv6.conf.lo.disable_ipv6=0",
      "sysctl -w net.ipv6.conf.all.forwarding=1", "sysctl -p",
      /* IPv4 */
      "iptables -P INPUT ACCEPT", "iptables -P FORWARD ACCEPT",
      "iptables -P OUTPUT ACCEPT",
      fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT",
          tun_net_interface_name_, out_net_interface_name_),
      fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT",
          out_net_interface_name_, tun_net_interface_name_),
      fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE",
          out_net_interface_name_),
      /* IPv6 */
      "ip6tables -P INPUT ACCEPT", "ip6tables -P FORWARD ACCEPT",
      "ip6tables -P OUTPUT ACCEPT",
      fmt::format("ip6tables -A FORWARD -i {} -o {} -j ACCEPT",
          tun_net_interface_name_, out_net_interface_name_),
      fmt::format("ip6tables -A FORWARD -i {} -o {} -j ACCEPT",
          out_net_interface_name_, tun_net_interface_name_),
      fmt::format("ip6tables -t nat -A POSTROUTING -o {} -j MASQUERADE",
          out_net_interface_name_)};
#elif __APPLE__
  // NEED CHECK
  const std::vector<std::string> commands = {
      fmt::format("echo 'set skip on lo0' > /tmp/pf.conf"),
      fmt::format("echo 'block in all' >> /tmp/pf.conf"),
      fmt::format("echo 'pass out all' >> /tmp/pf.conf"),
      fmt::format("echo 'block in on {} from any to any' >> /tmp/pf.conf",
          out_net_interface_name_),
      "pfctl -ef /tmp/pf.conf",
  };
#else
#error "Unsupported system!"
#endif
  SPDLOG_INFO("=== Setting up routing ===");
  try {
    for (const auto& cmd : commands) {
      if (!RunCommand(cmd)) {
        SPDLOG_ERROR("COMMAND ERROR: {}", cmd);
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception occurred while applying routing: {}", e.what());
    return false;
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred while applying routing.");
    return false;
  }
  SPDLOG_INFO("=== Routing setup completed successfully ===");
  return true;
}

// NOLINT(bugprone-exception-escape)
bool IPTables::Clean() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (!running_) {
    return true;
  }
#ifdef __linux__
  const std::vector<std::string> commands = {
      fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT",
          tun_net_interface_name_, out_net_interface_name_),
      fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT",
          out_net_interface_name_, tun_net_interface_name_),
      fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE",
          out_net_interface_name_)};
#elif __APPLE__
  const std::vector<std::string> commands = {
      "echo 'set skip on lo0' > /tmp/pf.conf",
      "echo 'block in all' >> /tmp/pf.conf",
      "echo 'pass out all' >> /tmp/pf.conf",
      fmt::format("echo 'pass in on {} from any to any' >> /tmp/pf.conf",
          out_net_interface_name_),
      fmt::format("echo 'pass in on {} from {} to any' >> /tmp/pf.conf",
          tun_net_interface_name_, tun_net_interface_name_),
      "pfctl -f /tmp/pf.conf", "pfctl -e"};
#else
#error "Unsupported system!"
#endif
  try {
    for (const auto& cmd : commands) {
      RunCommand(cmd);
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IPTables error: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined error");
  }
  running_ = false;
  return true;
}
