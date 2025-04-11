/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <vector>

namespace fptn::config {
class ConfigFile final {
 public:
  struct Server {
    std::string name;
    std::string host;
    int port;
    bool isUsing;

    // FIX USING FOR CLI
    std::string username;
    std::string password;
    std::string service_name;
  };

 public:
  explicit ConfigFile(std::string sni);
  explicit ConfigFile(std::string token, std::string sni);

  bool Parse();
  Server FindFastestServer() const;
  bool AddServer(const Server& s);

 public:
  int GetVersion() const noexcept;
  std::string GetServiceName() const noexcept;
  std::string GetUsername() const noexcept;
  std::string GetPassword() const noexcept;
  std::vector<Server> GetServers() const noexcept;

 public:
  std::uint64_t GetDownloadTimeMs(
      const Server& server, int timeout = 4) const noexcept;

 private:
  const std::string token_;
  const std::string sni_;

  int version_;
  std::string service_name_;
  std::string username_;
  std::string password_;
  std::vector<Server> servers_;
};
}  // namespace fptn::config
