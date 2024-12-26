
#include "antiscan.h"

#if defined(__APPLE__) || defined(__linux__)
#include <arpa/inet.h>
#elif _WIN32
#include <winsock2.h>
#endif


#include <common/network/ipv6_utils.h>


using namespace fptn::filter::packets;


AntiScanFilter::AntiScanFilter(
    /* IPv4 */
    const pcpp::IPv4Address& serverIPv4,
    const pcpp::IPv4Address& serverIpv4Net,
    const int serverIPv4Mask,
    /* IPv6 */
    const pcpp::IPv6Address& serverIPv6,
    const pcpp::IPv6Address& serverIpv6Net,
    const int serverIPv6Mask
)
    :
        BaseFilter(),
        serverIPv4_(ntohl(serverIPv4.toInt())),
        serverIPv4Net_(ntohl(serverIpv4Net.toInt())),
        serverIPv4Mask_((0xFFFFFFFF << (32 - serverIPv4Mask))),
        serverIPv6_(fptn::common::network::ipv6::toUInt128(serverIPv6)),
        serverIpv6Net_(fptn::common::network::ipv6::toUInt128(serverIpv6Net)),
        serverIPv6Mask_((boost::multiprecision::uint128_t(1) << (128 - serverIPv6Mask)) - 1)
{
}

IPPacketPtr AntiScanFilter::apply(IPPacketPtr packet) const noexcept
{
    // Prevent sending requests to the VPN virtual network from the client
    static pcpp::IPv4Address ipv4Broadcast("255.255.255.255");

    if (packet->isIPv4()) {
        const std::uint32_t dst = ntohl(packet->ipv4Layer()->getDstIPv4Address().toInt());
        const bool isInNetwork = (dst & serverIPv4Mask_) == (serverIPv4Net_ & serverIPv4Mask_);
        if (serverIPv4_ == dst || (!isInNetwork && ipv4Broadcast != packet->ipv4Layer()->getDstIPv4Address())) {
            return std::move(packet);
        }
    } else if (packet->isIPv6()) {
        const auto dst = fptn::common::network::ipv6::toUInt128(packet->ipv6Layer()->getDstIPv6Address());
        const auto maxAddr = serverIpv6Net_ | serverIPv6Mask_;
        const bool isInNetwork = (serverIpv6Net_ <= dst && dst <= maxAddr);
        if (serverIPv6_ == dst || !isInNetwork) {
            return std::move(packet);
        }
    }
    return nullptr;
}
