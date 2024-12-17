
#include "antiscan.h"

#include <arpa/inet.h>


using namespace fptn::filter::packets;


AntiScanFilter::AntiScanFilter(const pcpp::IPv4Address& net, const int mask)
        : BaseFilter(), net_(ntohl(net.toInt())), mask_((0xFFFFFFFF << (32 - mask)))
{
}

IPPacketPtr AntiScanFilter::apply(IPPacketPtr packet) const noexcept
{
    // Prevent sending requests to the VPN virtual network from the client
    static pcpp::IPv4Address broadcast("255.255.255.255");

    const std::uint32_t dst = ntohl(packet->ipLayer()->getDstIPv4Address().toInt());
    const bool netRequest = (dst & mask_) == (net_ & mask_);

    if (!netRequest && broadcast != packet->ipLayer()->getDstIPv4Address()) {
        return std::move(packet);
    }
    return nullptr;
}
