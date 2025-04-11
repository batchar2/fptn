/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "common/https/client.h"
#include "common/network/ip_packet.h"

#include "websocket/websocket.h"

namespace fptn::http {

class Client final {
 public:
  using NewIPPacketCallback =
      std::function<void(fptn::common::network::IPPacketPtr packet)>;

 public:
  Client(const pcpp::IPv4Address& server_ip,
      int server_port,
      const pcpp::IPv4Address& tun_interface_address_ipv4,
      const pcpp::IPv6Address& tun_interface_address_ipv6,
      const std::string& sni,
      const NewIPPacketCallback& new_ip_pkt_callback = nullptr);
  bool Login(const std::string& username, const std::string& password) noexcept;
  std::pair<pcpp::IPv4Address, pcpp::IPv6Address> GetDns() noexcept;
  bool Start() noexcept;
  bool Stop() noexcept;
  bool Send(fptn::common::network::IPPacketPtr packet) noexcept;
  void SetNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept;
  bool IsStarted() noexcept;

 protected:
  void Run() noexcept;

 private:
  std::thread th_;
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  const pcpp::IPv4Address server_ip_;
  const int server_port_;

  const pcpp::IPv4Address tun_interface_address_ipv4_;
  const pcpp::IPv6Address tun_interface_address_ipv6_;
  const std::string sni_;

  NewIPPacketCallback new_ip_pkt_callback_;

  std::string token_;
  WebsocketSPtr ws_;
};

using ClientPtr = std::unique_ptr<Client>;
}  // namespace fptn::http
