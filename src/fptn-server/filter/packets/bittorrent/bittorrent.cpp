
#include "bittorrent.h"

#include <cstring>

using namespace fptn::filter::packets;


static const std::uint8_t classicSignature[] = {0x13, 'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't', ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'};
static const std::uint8_t extensionProtocolSignature[] = {0x14, 'e', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n'};
static const std::uint8_t dhtSignature[] = {'d', '1', ':', 'a', 'd', '2', ':', 'i', 'd', '2'};


static bool detectBitTorrent(const std::uint8_t* payload, std::size_t payloadSize);


BitTorrentFilter::BitTorrentFilter()
    : BaseFilter()
{
}


IPPacketPtr BitTorrentFilter::apply(IPPacketPtr packet) const noexcept
{
    const pcpp::TcpLayer* tcp = packet->pkt().getLayerOfType<pcpp::TcpLayer>();
    if (tcp) { // TCP
        if (detectBitTorrent(tcp->getLayerPayload(), tcp->getLayerPayloadSize()) ) {
            return nullptr;
        }
    } else { // UDP
        const pcpp::UdpLayer* udp = packet->pkt().getLayerOfType<pcpp::UdpLayer>();
        if (udp) {
            if (detectBitTorrent(udp->getLayerPayload(), udp->getLayerPayloadSize()) ) {
                return nullptr;
            }
        }
    }
    return std::move(packet);
}


static bool detectBitTorrent(const std::uint8_t* payload, std::size_t payloadSize)
{
    // Classic Protocol
    constexpr std::size_t classicSignatureSize = sizeof(classicSignature);
    if (payloadSize >= classicSignatureSize) {
        if (std::memcmp(payload, classicSignature, classicSignatureSize) == 0) {
            return true;
        }
    }
    // Extension Protocol
    constexpr std::size_t extensionProtocolSignatureSize = sizeof(extensionProtocolSignature);
    if (payloadSize >= extensionProtocolSignatureSize) {
        if (std::memcmp(payload, extensionProtocolSignature, extensionProtocolSignatureSize) == 0) {
            return true;
        }
    }
    // BT-DHT
    constexpr std::size_t dhtSignatureSize = sizeof(dhtSignature);
    if (payloadSize >= dhtSignatureSize) {
        if (std::memcmp(payload, dhtSignature, dhtSignatureSize) == 0) {
            return true;
        }
    }
    return false;
}
