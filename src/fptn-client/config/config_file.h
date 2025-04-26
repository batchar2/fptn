/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <utility>
#include <vector>

#include "fptn-client-protocol-lib/server/speed_estimator.h"

namespace fptn::config {
class ConfigFile final {
 public:
  explicit ConfigFile(std::string sni);
  explicit ConfigFile(std::string token, std::string sni);

  bool Parse();
  fptn::client::protocol::lib::server::Server FindFastestServer() const;
  std::uint64_t GetDownloadTimeMs(
      fptn::client::protocol::lib::server::Server const& server,
      const std::string& sni,
      int const timeout);

  bool AddServer(const fptn::client::protocol::lib::server::Server& s);

  int GetVersion() const noexcept;
  const std::string& GetServiceName() const noexcept;
  const std::string& GetUsername() const noexcept;
  const std::string& GetPassword() const noexcept;
  const std::vector<fptn::client::protocol::lib::server::Server>& GetServers()
      const noexcept;

 private:
  const std::string token_;
  const std::string sni_;

  int version_;
  std::string service_name_;
  std::string username_;
  std::string password_;
  std::vector<fptn::client::protocol::lib::server::Server> servers_;
};
}  // namespace fptn::config
