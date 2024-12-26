#pragma once

#include <chrono>
#include <memory>
#include <unordered_map>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>

#include <common/client_id.h>

#include "traffic_shaper/leaky_bucket.h"

#include <iostream>


namespace fptn::client 
{

    class Session final
    {
    public:
        Session(
            ClientID clientId,
            const std::string& userName,
            const pcpp::IPv4Address& clientIPv4,
            const pcpp::IPv4Address& fakeClientIPv4,
            const pcpp::IPv6Address& clientIPv6,
            const pcpp::IPv6Address& fakeClientIPv6,
            const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperToClient,
            const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperFromClient
        );
        const ClientID& clientId() const noexcept;
        const std::string& userName() const noexcept;

        const pcpp::IPv4Address& clientIPv4() const noexcept;
        const pcpp::IPv4Address& fakeClientIPv4() const noexcept;
        const pcpp::IPv6Address& clientIPv6() const noexcept;
        const pcpp::IPv6Address& fakeClientIPv6() const noexcept;

        fptn::traffic_shaper::LeakyBucketSPtr& getTrafficShaperToClient() noexcept;
        fptn::traffic_shaper::LeakyBucketSPtr& getTrafficShaperFromClient() noexcept;

        fptn::common::network::IPPacketPtr changeIPAddressToClientIP(
                fptn::common::network::IPPacketPtr packet) noexcept;
        fptn::common::network::IPPacketPtr changeIPAddressToFakeIP(
                fptn::common::network::IPPacketPtr packet) noexcept;
    private:
        const ClientID clientId_;
        const std::string userName_;
        const pcpp::IPv4Address clientIPv4_;
        const pcpp::IPv4Address fakeClientIPv4_;
        const pcpp::IPv6Address clientIPv6_;
        const pcpp::IPv6Address fakeClientIPv6_;
        fptn::traffic_shaper::LeakyBucketSPtr trafficShaperToClient_;
        fptn::traffic_shaper::LeakyBucketSPtr trafficShaperFromClient_;
    };

    using SessionSPtr = std::shared_ptr<Session>;

}