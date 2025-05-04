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

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/websocket/websocket_client.h"

namespace fptn::http {

class Client final {
 public:
  using NewIPPacketCallback =
      std::function<void(fptn::common::network::IPPacketPtr packet)>;

 public:
  Client(pcpp::IPv4Address server_ip,
      int server_port,
      pcpp::IPv4Address tun_interface_address_ipv4,
      pcpp::IPv6Address tun_interface_address_ipv6,
      std::string sni,
      NewIPPacketCallback new_ip_pkt_callback = nullptr);
  bool Login(const std::string& username, const std::string& password);
  std::pair<pcpp::IPv4Address, pcpp::IPv6Address> GetDns();
  bool Start();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet);
  void SetNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept;
  bool IsStarted();

 protected:
  void Run();

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
  fptn::protocol::websocket::WebsocketClientSPtr ws_;
};

using ClientPtr = std::unique_ptr<Client>;
}  // namespace fptn::http
