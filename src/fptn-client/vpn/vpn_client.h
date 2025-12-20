/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <mutex>

#include <openssl/base.h>  // NOLINT(build/include_order)

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

#include "http/client.h"
#include "split/tunneling.h"

namespace fptn::vpn {
class VpnClient final {
 public:
  explicit VpnClient(fptn::vpn::http::ClientPtr http_client,
      fptn::common::network::TunInterfacePtr virtual_net_interface,
      fptn::common::network::IPv4Address dns_server_ipv4,
      fptn::common::network::IPv6Address dns_server_ipv6,
      fptn::split::TunnelingPtr tunneling = nullptr);
  ~VpnClient();
  bool Start();
  bool Stop();
  std::size_t GetSendRate();
  std::size_t GetReceiveRate();
  bool IsStarted();

 protected:
  void HandlePacketFromVirtualNetworkInterface(
      fptn::common::network::IPPacketPtr packet);
  void HandlePacketFromWebSocket(fptn::common::network::IPPacketPtr packet);

 private:
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  fptn::vpn::http::ClientPtr http_client_;
  fptn::common::network::TunInterfacePtr virtual_net_interface_;
  const fptn::common::network::IPv4Address dns_server_ipv4_;
  const fptn::common::network::IPv6Address dns_server_ipv6_;

  const fptn::split::TunnelingPtr tunneling_;
};

using VpnClientPtr = std::unique_ptr<fptn::vpn::VpnClient>;
}  // namespace fptn::vpn
