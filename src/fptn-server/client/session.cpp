#include "session.h"


using namespace fptn::client;


Session::Session(
    fptn::ClientID clientId,
    const std::string& userName,
    const pcpp::IPv4Address& clientIP, 
    const pcpp::IPv4Address& fakeClientIP,
    const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperToClient,
    const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperFromClient
) :
    clientId_(clientId),
    userName_(userName),
    clientIP_(clientIP),
    fakeClientIP_(fakeClientIP),
    trafficShaperToClient_(trafficShaperToClient),
    trafficShaperFromClient_(trafficShaperFromClient)
{
}

const fptn::ClientID& Session::clientId() const noexcept
{
    return clientId_;
}

const std::string& Session::userName() const noexcept
{
    return userName_;
}

const pcpp::IPv4Address& Session::clientIP() const noexcept
{
    return clientIP_;
}

const pcpp::IPv4Address& Session::fakeClientIP() const noexcept
{
    return fakeClientIP_;
}

fptn::traffic_shaper::LeakyBucketSPtr Session::getTrafficShaperToClient() noexcept
{
    return trafficShaperToClient_;
}

fptn::traffic_shaper::LeakyBucketSPtr Session::getTrafficShaperFromClient() noexcept
{
    return trafficShaperFromClient_;
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
    // if (packet->isDnsPacket())
    return packet;
}
