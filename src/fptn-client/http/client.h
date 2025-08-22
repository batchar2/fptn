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

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/websocket/websocket_client.h"

namespace fptn::http {

using IPv4Address = fptn::common::network::IPv4Address;
using IPv6Address = fptn::common::network::IPv6Address;

class Client final {
 public:
  using NewIPPacketCallback =
      std::function<void(fptn::common::network::IPPacketPtr packet)>;

 public:
  Client(IPv4Address server_ip,
      int server_port,
      IPv4Address tun_interface_address_ipv4,
      IPv6Address tun_interface_address_ipv6,
      std::string sni,
      std::string md5_fingerprint,
      NewIPPacketCallback new_ip_pkt_callback = nullptr);
  bool Login(const std::string& username, const std::string& password);
  std::pair<IPv4Address, IPv6Address> GetDns();
  bool Start();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet) const;
  void SetRecvIPPacketCallback(const NewIPPacketCallback& callback) noexcept;
  bool IsStarted();

  const std::string& LatestError() const;

 protected:
  void Run();

 private:
  const int kMaxReconnectionAttempts_ = 3;

  std::thread th_;
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  const IPv4Address server_ip_;
  const int server_port_;

  const IPv4Address tun_interface_address_ipv4_;
  const IPv6Address tun_interface_address_ipv6_;
  const std::string sni_;
  const std::string md5_fingerprint_;

  NewIPPacketCallback new_ip_pkt_callback_;

  std::string access_token_;
  fptn::protocol::websocket::WebsocketClientSPtr ws_;

  std::string latest_error_;

  std::atomic<int> reconnection_attempts_;
};

using ClientPtr = std::unique_ptr<Client>;
}  // namespace fptn::http
