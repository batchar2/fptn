#include "vpn_client.h"


#include <string>
#include <memory>
#include <functional>


using namespace fptn::vpn;


VpnClient::VpnClient(
    fptn::http::WebSocketClientPtr webSocket,
    fptn::common::network::BaseNetInterfacePtr virtualNetworkInterface
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
    if (virtualNetworkInterface_) {
        virtualNetworkInterface_->stop();
        virtualNetworkInterface_.reset();
    }
    if (webSocket_) {
        webSocket_->stop();
        webSocket_.reset();
    }
}


std::size_t VpnClient::getSendRate() noexcept
{
    return virtualNetworkInterface_->getSendRate();
}

std::size_t VpnClient::getReceiveRate() noexcept
{
    return virtualNetworkInterface_->getReceiveRate();
}

void VpnClient::packetFromVirtualNetworkInterface(fptn::common::network::IPPacketPtr packet) noexcept
{
    webSocket_->send(std::move(packet));
}

void VpnClient::packetFromWebSocket(fptn::common::network::IPPacketPtr packet) noexcept
{
    virtualNetworkInterface_->send(std::move(packet));
}
