/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "cmd/command_line_config.h"

#include <algorithm>
#include <memory>
#include <string>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

using fptn::cmd::CommandLineConfig;

namespace {
bool ParseBoolean(std::string value) noexcept {
  try {
    // С++17
    // NOLINTNEXTLINE(modernize-use-ranges)
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return value == "true";
  } catch (...) {
    return false;
  }
}
}  // namespace

CommandLineConfig::CommandLineConfig(int argc, char* argv[])
    : argc_(argc), argv_(argv), args_("fptn-server", FPTN_VERSION) {
  // Required arguments
  args_.add_argument("--server-crt").required().help("Path to server.crt file");
  args_.add_argument("--server-key").required().help("Path to server.key file");
  args_.add_argument("--server-pub").required().help("Path to server.pub file");
  args_.add_argument("--out-network-interface")
      .required()
      .help("Network out interface");
  // Optional arguments
  args_.add_argument("--server-port")
      .default_value(443)
      .help("Port number")
      .scan<'i', int>();
  args_.add_argument("--tun-interface-name")
      .default_value("tun0")
      .help("Network interface name");
  /* IPv4 */
  args_.add_argument("--tun-interface-ip")
      .default_value(FPTN_SERVER_DEFAULT_ADDRESS_IP4)
      .help("IP address of the virtual interface");
  args_.add_argument("--tun-interface-network-address")
      .default_value(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP4)
      .help("IP network of the virtual interface");
  args_.add_argument("--tun-interface-network-mask")
      .default_value(16)
      .help("Network mask")
      .scan<'i', int>();
  /* IPv6 */
  args_.add_argument("--tun-interface-ipv6")
      .default_value(FPTN_SERVER_DEFAULT_ADDRESS_IP6)
      .help("IPv6 address of the virtual interface");
  args_.add_argument("--tun-interface-network-ipv6-address")
      .default_value(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP6)
      .help("IPv6 network address of the virtual interface");
  args_.add_argument("--tun-interface-network-ipv6-mask")
      .default_value(64)
      .help("IPv6 network mask")
      .scan<'i', int>();
  args_.add_argument("--userfile")
      .help("Path to users file (default: /etc/fptn/users.list)")
      .default_value("/etc/fptn/users.list");
  // Packet filters
  args_.add_argument("--disable-bittorrent")
      .help(
          "Disable BitTorrent traffic filtering. Use this flag to disable "
          "filtering.")
      .default_value("false");
  // Allow prometheus metric
  args_.add_argument("--prometheus-access-key")
      .help(
          "Secret key required for accessing Prometheus metrics. Set this to a "
          "secret value if metrics is needed.")
      .default_value("");
  // Remote server auth
  args_.add_argument("--use-remote-server-auth")
      .help(
          "Enable remote server authentication. Set to 'true' to use a remote "
          "server for authentication.")
      .default_value("false");
  args_.add_argument("--remote-server-auth-host")
      .help(
          "Specify the remote server's IP address or hostname for "
          "authentication.")
      .default_value("1.1.1.1");
  args_.add_argument("--remote-server-auth-port")
      .help(
          "Specify the port number for the remote server authentication. Set "
          "to 0 to use the default port.")
      .default_value(443)
      .scan<'i', int>();
  // experimental
  args_.add_argument("--enable-detect-probing")
      .help(
          "Enable detection of non-FPTN clients or probing attempts during SSL "
          "handshake. ")
      .default_value("false");
}

bool CommandLineConfig::Parse() noexcept {  // NOLINT(bugprone-exception-escape)
  try {
    args_.parse_args(argc_, argv_);
    return true;
  } catch (const std::runtime_error& err) {
    const std::string help = args_.help().str();
    SPDLOG_ERROR("Argument parsing error: {}\n{}", err.what(), help);
  } catch (...) {
    SPDLOG_ERROR("Undefined parser error");
  }
  return false;
}

std::string CommandLineConfig::ServerCrt() const {
  return args_.get<std::string>("--server-crt");
}

std::string CommandLineConfig::ServerKey() const {
  return args_.get<std::string>("--server-key");
}

std::string CommandLineConfig::ServerPub() const {
  return args_.get<std::string>("--server-pub");
}

std::string CommandLineConfig::OutNetworkInterface() const {
  return args_.get<std::string>("--out-network-interface");
}

int CommandLineConfig::ServerPort() const {
  return args_.get<int>("--server-port");
}

std::string CommandLineConfig::TunInterfaceName() const {
  return args_.get<std::string>("--tun-interface-name");
}

pcpp::IPv4Address CommandLineConfig::TunInterfaceIPv4() const {
  return pcpp::IPv4Address(args_.get<std::string>("--tun-interface-ip"));
}

pcpp::IPv4Address CommandLineConfig::TunInterfaceNetworkIPv4Address() const {
  return pcpp::IPv4Address(
      args_.get<std::string>("--tun-interface-network-address"));
}

int CommandLineConfig::TunInterfaceNetworkIPv4Mask() const {
  return args_.get<int>("--tun-interface-network-mask");
}

pcpp::IPv6Address CommandLineConfig::TunInterfaceIPv6() const {
  return pcpp::IPv6Address(args_.get<std::string>("--tun-interface-ipv6"));
}

pcpp::IPv6Address CommandLineConfig::TunInterfaceNetworkIPv6Address() const {
  return pcpp::IPv6Address(
      args_.get<std::string>("--tun-interface-network-ipv6-address"));
}

int CommandLineConfig::TunInterfaceNetworkIPv6Mask() const {
  return args_.get<int>("--tun-interface-network-ipv6-mask");
}

std::string CommandLineConfig::UserFile() const {
  return args_.get<std::string>("--userfile");
}

bool CommandLineConfig::DisableBittorrent() const {
  return ParseBoolean(args_.get<std::string>("--disable-bittorrent"));
}

std::string CommandLineConfig::PrometheusAccessKey() const {
  return args_.get<std::string>("--prometheus-access-key");
}

bool CommandLineConfig::UseRemoteServerAuth() const {
  return ParseBoolean(args_.get<std::string>("--use-remote-server-auth"));
}

std::string CommandLineConfig::RemoteServerAuthHost() const {
  return args_.get<std::string>("--remote-server-auth-host");
}

int CommandLineConfig::RemoteServerAuthPort() const {
  return args_.get<int>("--remote-server-auth-port");
}

bool CommandLineConfig::EnableDetectProbing() const {
  return ParseBoolean(args_.get<std::string>("--enable-detect-probing"));
}
