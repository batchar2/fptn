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
//#ifdef _WIN32
            fptn::common::network::TapInterfacePtr virtualNetworkInterface
//#else
//    fptn::common::network::TunInterfacePtr virtualNetworkInterface
//#endif
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

//#ifdef _WIN32
        fptn::common::network::TapInterfacePtr virtualNetworkInterface_;
//#else
//        fptn::common::network::TunInterfacePtr virtualNetworkInterface_;
//#endif
    };

    using VpnClientPtr = std::unique_ptr<fptn::vpn::VpnClient>;
} 
