/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <functional>
#include <memory>
#include <string>

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

namespace fptn::protocol::https {

enum class HttpsInitConnectionStrategy : int {
  kSni = 0,
  kTlsObfuscator = 1,
  kSniRealityMode = 2
};

using IPv4Address = fptn::common::network::IPv4Address;
using IPv6Address = fptn::common::network::IPv6Address;

using RecvIPPacketCallback =
    std::function<void(fptn::common::network::IPPacketPtr packet)>;

using OnConnectedCallback = std::function<void()>;

struct ConnectionConfig {
  struct Common {
    IPv4Address server_ip;
    std::uint16_t server_port = 443;

    std::string sni;
    std::string md5_fingerprint;
    HttpsInitConnectionStrategy https_init_connection_strategy;

    IPv4Address tun_interface_address_ipv4;
    IPv6Address tun_interface_address_ipv6;

    std::size_t connection_timeout_ms = 10000;
    std::size_t max_reconnections = 5;

    OnConnectedCallback on_connected_callback = nullptr;
    RecvIPPacketCallback recv_ip_packet_callback = nullptr;
  } common;

  struct Pool {
    std::size_t size = 3;
    //   int max_requests_per_connection = 1000;
    //   bool prewarm = true;
  } pool;

  bool Validate() const {
    if (common.server_ip.ToString().empty()) {
      return false;
    }
    if (pool.size == 0) {
      return false;
    }
    return true;
  }
};
};  // namespace fptn::protocol::https
