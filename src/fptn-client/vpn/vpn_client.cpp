#include "vpn_client.h"


#include <string>
#include <memory>
#include <functional>


using namespace fptn::vpn;


VpnClient::VpnClient(
    fptn::http::WebSocketClientPtr webSocket, 
    fptn::common::network::TunInterfacePtr virtualNetworkInterface
)
    : 
        webSocket_(std::move(webSocket)), 
        virtualNetworkInterface_(std::move(virtualNetworkInterface))
{
}

VpnClient::~VpnClient()
{
    stop();
}

void VpnClient::start() noexcept
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

void VpnClient::stop() noexcept
{
    webSocket_->stop();
    virtualNetworkInterface_->stop();
}

void VpnClient::packetFromVirtualNetworkInterface(fptn::common::network::IPPacketPtr packet) noexcept
{
    webSocket_->send(std::move(packet));
}

void VpnClient::packetFromWebSocket(fptn::common::network::IPPacketPtr packet) noexcept
{
    virtualNetworkInterface_->send(std::move(packet));
}
