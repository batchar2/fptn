/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>

#include <argparse/argparse.hpp>     // NOLINT(build/include_order)
#include <pcapplusplus/IpAddress.h>  // NOLINT(build/include_order)

namespace fptn::cmd {
class CommandLineConfig {
 public:
  explicit CommandLineConfig(int argc, char* argv[]);
  bool Parse() noexcept;

 public:
  /* options */
  [[nodiscard]] std::string ServerCrt() const;
  [[nodiscard]] std::string ServerKey() const;
  [[nodiscard]] std::string ServerPub() const;
  [[nodiscard]] std::string OutNetworkInterface() const;
  [[nodiscard]] int ServerPort() const;

  [[nodiscard]] std::string TunInterfaceName() const;
  /* IPv4 */
  [[nodiscard]] pcpp::IPv4Address TunInterfaceIPv4() const;
  [[nodiscard]] pcpp::IPv4Address TunInterfaceNetworkIPv4Address() const;
  [[nodiscard]] int TunInterfaceNetworkIPv4Mask() const;
  /* IPv6 */
  [[nodiscard]] pcpp::IPv6Address TunInterfaceIPv6() const;
  [[nodiscard]] pcpp::IPv6Address TunInterfaceNetworkIPv6Address() const;
  [[nodiscard]] int TunInterfaceNetworkIPv6Mask() const;

  [[nodiscard]] std::string UserFile() const;
  [[nodiscard]] bool DisableBittorrent() const;
  [[nodiscard]] std::string PrometheusAccessKey() const;

  [[nodiscard]] bool UseRemoteServerAuth() const;
  [[nodiscard]] std::string RemoteServerAuthHost() const;
  [[nodiscard]] int RemoteServerAuthPort() const;

  [[nodiscard]] bool EnableDetectProbing() const;

 private:
  int argc_;
  char** argv_;
  argparse::ArgumentParser args_;
};

}  // namespace fptn::cmd
