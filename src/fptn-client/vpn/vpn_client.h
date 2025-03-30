#pragma once

#include <memory>
#include <common/network/ip_packet.h>
#include <common/network/net_interface.h>

#include "http/client.h"


namespace fptn::vpn
{
    class VpnClient final
    {
    public:
        explicit VpnClient(
            fptn::http::ClientPtr httpClient,
            fptn::common::network::BaseNetInterfacePtr virtualNetworkInterface,
            const pcpp::IPv4Address& dnsServerIPv4,
            const pcpp::IPv6Address& dnsServerIPv6
        );
        ~VpnClient();
        void start() noexcept;
        void stop() noexcept;
        std::size_t getSendRate() noexcept;
        std::size_t getReceiveRate() noexcept;
        bool isStarted() noexcept;
    private:
        void packetFromVirtualNetworkInterface(fptn::common::network::IPPacketPtr packet) noexcept;
        void packetFromWebSocket(fptn::common::network::IPPacketPtr packet) noexcept;
    private:
        fptn::http::ClientPtr httpClient_;
        fptn::common::network::BaseNetInterfacePtr virtualNetworkInterface_;
        const pcpp::IPv4Address dnsServerIPv4_;
        const pcpp::IPv6Address dnsServerIPv6_;
    };

    using VpnClientPtr = std::unique_ptr<fptn::vpn::VpnClient>;
} 
