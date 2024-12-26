#pragma once

#include <chrono>
#include <memory>
#include <unordered_map>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>

#include <common/network/ipv4_generator.h>
#include <common/network/ipv6_generator.h>

#include "client/session.h"
#include "statistic/metrics.h"
#include "traffic_shaper/leaky_bucket.h"


namespace fptn::nat 
{
    class Table final
    {
        using IPv4INT = std::uint32_t;
    public:
        Table(const pcpp::IPv4Address& tunInterfaceIPv4,
            const pcpp::IPv4Address& tunInterfaceIPv4NetworkAddress,
            const std::uint32_t tunInterfaceNetworkIPv4Mask,
            const pcpp::IPv6Address& tunInterfaceIPv6,
            const pcpp::IPv6Address& tunInterfaceIPv6NetworkAddress,
            const std::uint32_t tunInterfaceNetworkIPv6Mask
        );
        fptn::client::SessionSPtr createClientSession(ClientID clientId,
                                                      const std::string& userName,
                                                      const pcpp::IPv4Address& clientIPv4,
                                                      const pcpp::IPv6Address& clientIPv6,
                                                      const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperToClient,
                                                      const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperFromClient) noexcept;
        bool delClientSession(ClientID clientId) noexcept;
        void updateStatistic(fptn::statistic::MetricsSPtr& prometheus) noexcept;
    public:
        fptn::client::SessionSPtr getSessionByFakeIPv4(const pcpp::IPv4Address& ip) noexcept;
        fptn::client::SessionSPtr getSessionByFakeIPv6(const pcpp::IPv6Address& ip) noexcept;
        fptn::client::SessionSPtr getSessionByClientId(ClientID clientId) noexcept;
    private:
        pcpp::IPv4Address getUniqueIPv4Address();
        pcpp::IPv6Address getUniqueIPv6Address();
    private:
        mutable std::mutex mutex_;
        std::uint32_t clientNumber_;
        pcpp::IPv4Address tunInterfaceIPv4_;
        pcpp::IPv6Address tunInterfaceIPv6_;

        fptn::common::network::IPv4AddressGenerator ipv4Generator_;
        fptn::common::network::IPv6AddressGenerator ipv6Generator_;

        std::unordered_map<IPv4INT, fptn::client::SessionSPtr> ipv4ToSessions_; // ipv4
        std::unordered_map<std::string, fptn::client::SessionSPtr> ipv6ToSessions_;  // ipv6

        std::unordered_map<ClientID, fptn::client::SessionSPtr> clientIdToSessions_;
    };

    typedef std::shared_ptr<Table> TableSPtr;

}
