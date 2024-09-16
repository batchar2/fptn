#pragma once

#include <memory>
#include <common/network/ip_packet.h>
#include <common/network/net_interface.h>

#include "http/websocket_client.h"


namespace fptn::vpn
{
    class VpnClient final
    {
    public:
        VpnClient(
            fptn::http::WebSocketClientPtr webSocket,
            fptn::common::network::BaseNetInterfacePtr virtualNetworkInterface,
            const std::string& dnsServer  // FIX THIS
        );
        ~VpnClient();
        void start() noexcept;
        void stop() noexcept;
        std::size_t getSendRate() noexcept;
        std::size_t getReceiveRate() noexcept;
    private:
        void packetFromVirtualNetworkInterface(fptn::common::network::IPPacketPtr packet) noexcept;
        void packetFromWebSocket(fptn::common::network::IPPacketPtr packet) noexcept;
    private:
        fptn::http::WebSocketClientPtr webSocket_;
        fptn::common::network::BaseNetInterfacePtr virtualNetworkInterface_;
        pcpp::IPv4Address dnsServer_;
    };

    using VpnClientPtr = std::unique_ptr<fptn::vpn::VpnClient>;
} 
