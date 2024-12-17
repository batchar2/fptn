#pragma once

#include <filter/packets/base.h>


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
        AntiScanFilter(const pcpp::IPv4Address& serverIp, const pcpp::IPv4Address& net, const int mask);
        virtual IPPacketPtr apply(IPPacketPtr packet) const noexcept override;
        virtual ~AntiScanFilter() = default;
    private:
        const std::uint32_t serverIp_;
        const std::uint32_t net_;
        const int mask_;
    };
}
