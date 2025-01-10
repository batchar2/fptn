#include "session.h"


using namespace fptn::client;


Session::Session(
    fptn::ClientID clientId,
    const std::string& userName,
    const pcpp::IPv4Address& clientIPv4,
    const pcpp::IPv4Address& fakeClientIPv4,
    const pcpp::IPv6Address& clientIPv6,
    const pcpp::IPv6Address& fakeClientIPv6,
    const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperToClient,
    const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperFromClient
) :
    clientId_(clientId),
    userName_(userName),
    clientIPv4_(clientIPv4),
    fakeClientIPv4_(fakeClientIPv4),
    clientIPv6_(clientIPv6),
    fakeClientIPv6_(fakeClientIPv6),
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

const pcpp::IPv4Address& Session::clientIPv4() const noexcept
{
    return clientIPv4_;
}

const pcpp::IPv4Address& Session::fakeClientIPv4() const noexcept
{
    return fakeClientIPv4_;
}

const pcpp::IPv6Address& Session::clientIPv6() const noexcept
{
    return clientIPv6_;
}

const pcpp::IPv6Address& Session::fakeClientIPv6() const noexcept
{
    return fakeClientIPv6_;
}

fptn::traffic_shaper::LeakyBucketSPtr& Session::getTrafficShaperToClient() noexcept
{
    return trafficShaperToClient_;
}

fptn::traffic_shaper::LeakyBucketSPtr& Session::getTrafficShaperFromClient() noexcept
{
    return trafficShaperFromClient_;
}

fptn::common::network::IPPacketPtr Session::changeIPAddressToClientIP(fptn::common::network::IPPacketPtr packet) noexcept
{
    packet->setClientId(clientId_);
    if (packet->isIPv4()) {
        packet->setDstIPv4Address(clientIPv4_);
    } else if (packet->isIPv6()) {
        packet->setDstIPv6Address(clientIPv6_);
    }
    packet->computeCalculateFields();
    return packet;
}

fptn::common::network::IPPacketPtr Session::changeIPAddressToFakeIP(fptn::common::network::IPPacketPtr packet) noexcept
{
    packet->setClientId(clientId_);
    if (packet->isIPv4()) {
        packet->setSrcIPv4Address(fakeClientIPv4_);
    } else if (packet->isIPv6()) {
        packet->setSrcIPv6Address(fakeClientIPv6_);
    }
    packet->computeCalculateFields();
    return packet;
}
