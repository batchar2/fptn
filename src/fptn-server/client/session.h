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
            const pcpp::IPv4Address& clientIP, 
            const pcpp::IPv4Address& fakeClientIP,
            const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaper
        );
        const ClientID clientId() const noexcept;
        const pcpp::IPv4Address& clientIP() const noexcept;
        const pcpp::IPv4Address& fakeClientIP() const noexcept;
        fptn::traffic_shaper::LeakyBucketSPtr getTrafficShaper() noexcept;
        fptn::common::network::IPPacketPtr changeIPAddressToCleintIP(
                fptn::common::network::IPPacketPtr packet) noexcept;
        fptn::common::network::IPPacketPtr changeIPAddressToFakeIP(
                fptn::common::network::IPPacketPtr packet) noexcept;
    private:
        const ClientID clientId_;
        const pcpp::IPv4Address clientIP_;
        const pcpp::IPv4Address fakeClientIP_;
        fptn::traffic_shaper::LeakyBucketSPtr trafficShaper_;
    };

    using SessionSPtr = std::shared_ptr<Session>;

}