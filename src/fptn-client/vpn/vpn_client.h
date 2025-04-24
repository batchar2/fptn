/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>

#include <openssl/base.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

#include "http/client.h"

namespace fptn::vpn {
class VpnClient final {
 public:
  explicit VpnClient(fptn::http::ClientPtr http_client,
      fptn::common::network::BaseNetInterfacePtr virtual_net_interface,
      const pcpp::IPv4Address& dns_server_ipv4,
      const pcpp::IPv6Address& dns_server_ipv6);
  ~VpnClient();
  void Start() noexcept;
  void Stop() noexcept;
  std::size_t GetSendRate() noexcept;
  std::size_t GetReceiveRate() noexcept;
  bool IsStarted() noexcept;

 protected:
  void HandlePacketFromVirtualNetworkInterface(
      fptn::common::network::IPPacketPtr packet) noexcept;
  void HandlePacketFromWebSocket(
      fptn::common::network::IPPacketPtr packet) noexcept;

 private:
  fptn::http::ClientPtr http_client_;
  fptn::common::network::BaseNetInterfacePtr virtual_net_interface_;
  const pcpp::IPv4Address dns_server_ipv4_;
  const pcpp::IPv6Address dns_server_ipv6_;
};

using VpnClientPtr = std::unique_ptr<fptn::vpn::VpnClient>;
}  // namespace fptn::vpn
