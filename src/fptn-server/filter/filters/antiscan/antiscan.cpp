/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/antiscan/antiscan.h"

#if defined(__APPLE__) || defined(__linux__)
#include <arpa/inet.h>
#elif _WIN32
#pragma warning(disable : 4996)
#include <Winsock2.h>
#pragma warning(default : 4996)
#endif

#include <common/network/ipv6_utils.h>

using fptn::common::network::IPPacketPtr;
using fptn::filter::AntiScan;

AntiScan::AntiScan(
    /* IPv4 */
    const fptn::common::network::IPv4Address& server_ipv4,
    const fptn::common::network::IPv4Address& server_ipv4_net,
    const int serverIPv4Mask,
    /* IPv6 */
    const fptn::common::network::IPv6Address& server_ipv6,
    const fptn::common::network::IPv6Address& server_ipv6_net,
    const int serverIPv6Mask)
    : server_ipv4_(ntohl(server_ipv4.ToInt())),
      server_ipv4_net_(ntohl(server_ipv4_net.ToInt())),
      server_ipv4_mask_((0xFFFFFFFF << (32 - serverIPv4Mask))),
      server_ipv6_(
          fptn::common::network::ipv6::toUInt128(server_ipv6.ToString())),
      server_ipv6_net_(
          fptn::common::network::ipv6::toUInt128(server_ipv6_net.ToString())),
      server_ipv6_mask_(
          (boost::multiprecision::uint128_t(1) << (128 - serverIPv6Mask)) - 1) {
}

IPPacketPtr AntiScan::apply(IPPacketPtr packet) const {
  // Prevent sending requests to the VPN virtual network from the client
  static fptn::common::network::IPv4Address ipv4_broadcast("255.255.255.255");
  static std::uint32_t ipv4_broadcast_int = ntohl(ipv4_broadcast.ToInt());

  if (packet->IsIPv4()) {
    const std::uint32_t dst =
        ntohl(packet->IPv4Layer()->getDstIPv4Address().toInt());
    const bool is_in_network =
        (dst & server_ipv4_mask_) == (server_ipv4_net_ & server_ipv4_mask_);
    if (server_ipv4_ == dst || (!is_in_network && ipv4_broadcast_int != dst)) {
      return packet;
    }
  } else if (packet->IsIPv6()) {
    const auto dst = fptn::common::network::ipv6::toUInt128(
        packet->IPv6Layer()->getDstIPv6Address());
    const auto max_addr = server_ipv6_net_ | server_ipv6_mask_;
    const bool is_in_network = (server_ipv6_net_ <= dst && dst <= max_addr);
    if (server_ipv6_ == dst || !is_in_network) {
      return packet;
    }
  }
  return nullptr;
}
