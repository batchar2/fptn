#pragma once

#include <string>
#include <memory>
#include <functional>

#include <common/network/ip_packet.h>
#include <common/network/tun_interface.h>

#include "http/websocket_client.h"


namespace fptn::vpn
{

    class VpnClient 
    {
    public:
        VpnClient(
            fptn::http::WebSocketClientPtr webSocket, 
            fptn::common::network::TunInterfacePtr virtualNetworkInterface
        )
            : 
                webSocket_(std::move(webSocket)), 
                virtualNetworkInterface_(std::move(virtualNetworkInterface))
        {
        }
        ~VpnClient()
        {
            stop();
        }
        void start()
        {
            webSocket_->setNewIPPacketCallback(
                std::bind(&VpnClient::packetFromWebSocket, this, std::placeholders::_1)
            );

            virtualNetworkInterface_->setNewIPPacketCallback(
                std::bind(&VpnClient::packetFromVirtualNetworkInterface, this, std::placeholders::_1)
            );

            webSocket_->start();
            virtualNetworkInterface_->start();
        }
        void stop()
        {
            webSocket_->stop();
            virtualNetworkInterface_->stop();
        }
    private:
        void packetFromVirtualNetworkInterface(fptn::common::network::IPPacketPtr packet)
        {
            webSocket_->send(std::move(packet));
        }
        void packetFromWebSocket(fptn::common::network::IPPacketPtr packet)
        {
            virtualNetworkInterface_->send(std::move(packet));
        }
    private:
        fptn::http::WebSocketClientPtr webSocket_;
        fptn::common::network::TunInterfacePtr virtualNetworkInterface_;
    };

    // auto virtualNetworkInterface = std::make_unique<fptn::common::network::TunInterface>(
    //     tunInterfaceName, tunInterfaceAddress, 30, nullptr
    // );

    //     )
    // }
} 