/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/filters/bittorrent/bittorrent.h"

#include <cstdint>
#include <cstring>

using fptn::common::network::IPPacketPtr;
using fptn::filter::BitTorrent;

static constexpr std::uint8_t kClassic[] = {0x13, 'B', 'i', 't', 'T', 'o', 'r',
    'r', 'e', 'n', 't', ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};

static constexpr std::uint8_t kExtensionProtocol[] = {
    0x14, 'e', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n'};

static constexpr std::uint8_t kDht[] = {
    'd', '1', ':', 'a', 'd', '2', ':', 'i', 'd', '2'};

namespace {

bool DetectBitTorrent(const std::uint8_t* payload, std::size_t payload_size) {
  if (!payload_size) {
    return false;
  }
  const std::uint8_t first_byte = payload[0];
  // Classic Protocol
  if (first_byte == kClassic[0]) {
    constexpr std::size_t kClassicSignatureSize = sizeof(kClassic);
    return payload_size >= kClassicSignatureSize &&
           std::memcmp(payload, kClassic, kClassicSignatureSize) == 0;
  }

  // Extension Protocol
  if (first_byte == kExtensionProtocol[0]) {
    constexpr std::size_t kExtProtocolSignSize = sizeof(kExtensionProtocol);
    return payload_size >= kExtProtocolSignSize &&
           std::memcmp(payload, kExtensionProtocol, kExtProtocolSignSize) == 0;
  }

  // BT-DHT
  if (first_byte == kDht[0]) {
    constexpr std::size_t kDhtSignatureSize = sizeof(kDht);
    return payload_size >= kDhtSignatureSize &&
           std::memcmp(payload, kDht, kDhtSignatureSize) == 0;
  }
  return false;
}

}  // namespace

IPPacketPtr BitTorrent::apply(IPPacketPtr packet) const {
  if (const auto* tcp = packet->Pkt().getLayerOfType<pcpp::TcpLayer>()) {
    if (DetectBitTorrent(tcp->getLayerPayload(), tcp->getLayerPayloadSize())) {
      return nullptr;
    }
  } else if (const auto* udp = packet->Pkt().getLayerOfType<pcpp::UdpLayer>()) {
    if (DetectBitTorrent(udp->getLayerPayload(), udp->getLayerPayloadSize())) {
      return nullptr;
    }
  }
  return packet;
}
