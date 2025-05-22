/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/bittorrent/bittorrent.h"

#include <cstdint>
#include <cstring>

using fptn::common::network::IPPacketPtr;
using fptn::filter::BitTorrent;

static const std::uint8_t kClassicSignature[] = {0x13, 'B', 'i', 't', 'T', 'o',
    'r', 'r', 'e', 'n', 't', ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};

static const std::uint8_t kExtensionProtocolSignature[] = {
    0x14, 'e', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n'};

static const std::uint8_t kDhtSignature[] = {
    'd', '1', ':', 'a', 'd', '2', ':', 'i', 'd', '2'};

namespace {

bool DetectBitTorrent(const std::uint8_t* payload, std::size_t payload_size) {
  // Classic Protocol
  constexpr std::size_t kClassicSignatureSize = sizeof(kClassicSignature);
  if (payload_size >= kClassicSignatureSize) {
    if (std::memcmp(payload, kClassicSignature, kClassicSignatureSize) == 0) {
      return true;
    }
  }
  // Extension Protocol
  constexpr std::size_t kExtensionProtocolSignatureSize =
      sizeof(kExtensionProtocolSignature);
  if (payload_size >= kExtensionProtocolSignatureSize) {
    if (std::memcmp(payload, kExtensionProtocolSignature,
            kExtensionProtocolSignatureSize) == 0) {
      return true;
    }
  }
  // BT-DHT
  constexpr std::size_t kDhtSignatureSize = sizeof(kDhtSignature);
  if (payload_size >= kDhtSignatureSize) {
    if (std::memcmp(payload, kDhtSignature, kDhtSignatureSize) == 0) {
      return true;
    }
  }
  return false;
}
}  // namespace

IPPacketPtr BitTorrent::apply(IPPacketPtr packet) const noexcept {
  const pcpp::TcpLayer* tcp = packet->Pkt().getLayerOfType<pcpp::TcpLayer>();
  if (tcp) {  // TCP
    if (DetectBitTorrent(tcp->getLayerPayload(), tcp->getLayerPayloadSize())) {
      return nullptr;
    }
  } else {  // UDP
    const pcpp::UdpLayer* udp = packet->Pkt().getLayerOfType<pcpp::UdpLayer>();
    if (udp) {
      if (DetectBitTorrent(
              udp->getLayerPayload(), udp->getLayerPayloadSize())) {
        return nullptr;
      }
    }
  }
  return packet;
}
