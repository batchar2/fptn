#include "session.h"


using namespace fptn::client;


Session::Session(
    fptn::ClientID clientId, 
    const pcpp::IPv4Address& clientIP, 
    const pcpp::IPv4Address& fakeClientIP,
    fptn::traffic_shaper::LeakyBucketSPtr trafficShaper
) :
    clientId_(clientId), clientIP_(clientIP), fakeClientIP_(fakeClientIP), trafficShaper_(trafficShaper)
{
}

const fptn::ClientID Session::clientId() const noexcept
{
    return clientId_;
}

const pcpp::IPv4Address& Session::clientIP() const noexcept
{
    return clientIP_;
}

const pcpp::IPv4Address& Session::fakeClientIP() const noexcept
{
    return fakeClientIP_;
}

fptn::traffic_shaper::LeakyBucketSPtr Session::getTrafficShaper() noexcept
{
    return trafficShaper_;
}

fptn::common::network::IPPacketPtr Session::changeIPAddressToCleintIP(fptn::common::network::IPPacketPtr packet) noexcept
{
    packet->setClientId(clientId_);
    packet->ipLayer()->getIPv4Header()->timeToLive -= 1;
    packet->ipLayer()->setDstIPv4Address(clientIP_);
    packet->computeCalculateFields();
    return packet;
}

fptn::common::network::IPPacketPtr Session::changeIPAddressToFakeIP(fptn::common::network::IPPacketPtr packet) noexcept
{
    packet->setClientId(clientId_);
    packet->ipLayer()->getIPv4Header()->timeToLive -= 1;
    packet->ipLayer()->setSrcIPv4Address(fakeClientIP_);
    packet->computeCalculateFields();
    return packet;
}
