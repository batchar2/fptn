
#include "antiscan.h"

#if defined(__APPLE__) || defined(__linux__)
    #include <arpa/inet.h>
#elif _WIN32
    #include <winsock2.h>
#else
    #error "Unsupported system!"
#endif


using namespace fptn::filter::packets;


AntiScanFilter::AntiScanFilter(const pcpp::IPv4Address& serverIp, const pcpp::IPv4Address& net, const int mask)
        : BaseFilter(), serverIp_(ntohl(serverIp.toInt())), net_(ntohl(net.toInt())), mask_((0xFFFFFFFF << (32 - mask)))
{
}

IPPacketPtr AntiScanFilter::apply(IPPacketPtr packet) const noexcept
{
    // Prevent sending requests to the VPN virtual network from the client
    static pcpp::IPv4Address broadcast("255.255.255.255");

    const std::uint32_t dst = ntohl(packet->ipLayer()->getDstIPv4Address().toInt());
    const bool netRequest = (dst & mask_) == (net_ & mask_);

    if (serverIp_ == dst || (!netRequest && broadcast != packet->ipLayer()->getDstIPv4Address())) {
        return std::move(packet);
    }
    return nullptr;
}
