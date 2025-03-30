#include "vpn_client.h"


#include <string>
#include <memory>
#include <functional>


using namespace fptn::vpn;


VpnClient::VpnClient(
    fptn::http::ClientPtr httpClient,
    fptn::common::network::BaseNetInterfacePtr virtualNetworkInterface,
    const pcpp::IPv4Address& dnsServerIPv4,
    const pcpp::IPv6Address& dnsServerIPv6
)
    :
        httpClient_(std::move(httpClient)),
        virtualNetworkInterface_(std::move(virtualNetworkInterface)),
        dnsServerIPv4_(dnsServerIPv4),
        dnsServerIPv6_(dnsServerIPv6)
{
}

VpnClient::~VpnClient()
{
    stop();
}

bool VpnClient::isStarted() noexcept
{
    return httpClient_ && httpClient_->isStarted();
}

void VpnClient::start() noexcept
{
    httpClient_->setNewIPPacketCallback(
        std::bind(&VpnClient::packetFromWebSocket, this, std::placeholders::_1)
    );

    virtualNetworkInterface_->setNewIPPacketCallback(
        std::bind(&VpnClient::packetFromVirtualNetworkInterface, this, std::placeholders::_1)
    );

    httpClient_->start();
    virtualNetworkInterface_->start();
}

void VpnClient::stop() noexcept
{
    if (httpClient_) {
        httpClient_->stop();
        httpClient_.reset();
    }
    if (virtualNetworkInterface_) {
        virtualNetworkInterface_->stop();
        virtualNetworkInterface_.reset();
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
    httpClient_->send(std::move(packet));
}

void VpnClient::packetFromWebSocket(fptn::common::network::IPPacketPtr packet) noexcept
{
    virtualNetworkInterface_->send(std::move(packet));
}
