#pragma once

#include <filter/packets/base.h>

#include <boost/multiprecision/cpp_int.hpp>


namespace fptn::filter::packets
{

    using namespace fptn::common::network;

    /**
     * @class AntiScanFilter
     * @brief A filter class that blocks packets from IP addresses belonging to a specific network.
     *
     * This class is used to block IP packets that match a given network address and subnet mask.
     * It compares the destination IP address of the packet against the specified network and mask.
     * If the packet belongs to the network, it is blocked.
     *
     * @note This filter does not modify the packets that are not blocked. It simply returns `nullptr` for blocked packets.
     */
    class AntiScanFilter : public BaseFilter
    {
    public:
        AntiScanFilter(
            /* IPv4 */
            const pcpp::IPv4Address& serverIPv4,
            const pcpp::IPv4Address& serverIpv4Net,
            const int serverIPv4Mask,
            /* IPv6 */
            const pcpp::IPv6Address& serverIPv6,
            const pcpp::IPv6Address& serverIpv6Net,
            const int serverIPv6Mask
        );
        virtual IPPacketPtr apply(IPPacketPtr packet) const noexcept override;
        virtual ~AntiScanFilter() = default;
    private:
        /* IPv4 */
        const std::uint32_t serverIPv4_;
        const std::uint32_t serverIPv4Net_;
        const int serverIPv4Mask_;

        /* IPv6 */
        const boost::multiprecision::uint128_t serverIPv6_;
        const boost::multiprecision::uint128_t serverIpv6Net_;
        const boost::multiprecision::uint128_t serverIPv6Mask_;
    };
}
