#pragma once

#include <chrono>
#include <memory>
#include <unordered_map>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>

#include "client/session.h"
#include "traffic_shaper/leaky_bucket.h"



namespace fptn::nat 
{
    class Table final
    {
        using IPv4INT = std::uint32_t;
    public:
        Table(const std::string virutalVpnNetwork, std::uint32_t virutalVpnNetworkMask);
        fptn::client::SessionSPtr createClientSession(ClientID clientId, const pcpp::IPv4Address& clientIP, fptn::traffic_shaper::LeakyBucketSPtr trafficShaper) noexcept;
        bool delClientSession(ClientID clientId) noexcept;
    public:
        fptn::client::SessionSPtr getSessionByFakeIP(const pcpp::IPv4Address& ip) noexcept;
        fptn::client::SessionSPtr getSessionByClientId(ClientID clientId) noexcept;
    private:
        std::mutex mutex_;
        std::unordered_map<IPv4INT, fptn::client::SessionSPtr> ipToSessions_;
        std::unordered_map<ClientID, fptn::client::SessionSPtr> clientIdToSessions_;

        std::uint32_t clientNumber_;
    };

    typedef std::shared_ptr<Table> TableSPtr;

}
