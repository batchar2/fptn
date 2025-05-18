/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <utility>

namespace fptn::protocol::server {

struct ServerInfo {
  std::string name;
  std::string host;
  int port;
  bool is_using;
  std::string md5_fingerprint;

  std::string username;
  std::string password;
  std::string service_name;

  ServerInfo() : port(0), is_using(false) {}

  ServerInfo(std::string _name,
      std::string _host,
      int _port,
      std::string _md5_fingerprint)
      : name(std::move(_name)),
        host(std::move(_host)),
        port(_port),
        is_using(false),
        md5_fingerprint(std::move(_md5_fingerprint)) {}
};

}  // namespace fptn::protocol::server
