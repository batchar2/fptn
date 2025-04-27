/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <utility>
#include <vector>

#include "fptn-protocol-lib/server/server_info.h"
#include "fptn-protocol-lib/server/speed_estimator.h"

namespace fptn::config {
class ConfigFile final {
 public:
  explicit ConfigFile(std::string sni);
  explicit ConfigFile(std::string token, std::string sni);

  bool Parse();
  fptn::protocol::server::ServerInfo FindFastestServer() const;
  std::uint64_t GetDownloadTimeMs(
      const fptn::protocol::server::ServerInfo& server,
      const std::string& sni,
      int timeout);

  bool AddServer(const fptn::protocol::server::ServerInfo& s);

  int GetVersion() const noexcept;
  const std::string& GetServiceName() const noexcept;
  const std::string& GetUsername() const noexcept;
  const std::string& GetPassword() const noexcept;
  const std::vector<fptn::protocol::server::ServerInfo>& GetServers()
      const noexcept;

 private:
  const std::string token_;
  const std::string sni_;

  int version_;
  std::string service_name_;
  std::string username_;
  std::string password_;
  std::vector<fptn::protocol::server::ServerInfo> servers_;
};
}  // namespace fptn::config
