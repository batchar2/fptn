#include "table.h"

using namespace fptn::nat;


Table::Table(const std::string virutalVpnNetwork, std::uint32_t virutalVpnNetworkMask)
    : clientNumber_(2)
{
}

fptn::client::SessionSPtr Table::createClientSession(ClientID clientId, const pcpp::IPv4Address& clientIP, fptn::traffic_shaper::LeakyBucketSPtr trafficShaper) noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (clientIdToSessions_.find(clientId) == clientIdToSessions_.end()) {
        clientNumber_ += 1;
        const pcpp::IPv4Address fakeIp(std::string("2.2.0.") + std::to_string(clientNumber_));  // FOR DEMO TEST

        auto session = std::make_shared<fptn::client::Session>(clientId, clientIP, fakeIp, trafficShaper);
        ipToSessions_.insert({fakeIp.toInt(), session});
        clientIdToSessions_.insert({clientId, session});
        return session;
    }
    return nullptr;
}

bool Table::delClientSession(ClientID clientId) noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto it = clientIdToSessions_.find(clientId);
    if (it != clientIdToSessions_.end()) {
        const IPv4INT ipInt = it->second->fakeClientIP().toInt();
        clientIdToSessions_.erase(it);
        {
            auto it_ip = ipToSessions_.find(ipInt);
            if (it_ip != ipToSessions_.end()) {
                ipToSessions_.erase(it_ip);
                return true;
            }
        }
    }
    return false;
}

fptn::client::SessionSPtr Table::getSessionByFakeIP(const pcpp::IPv4Address& ip) noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto it = ipToSessions_.find(ip.toInt());
    if (it != ipToSessions_.end()) {
        return it->second;
    }
    return nullptr;
}

fptn::client::SessionSPtr Table::getSessionByClientId(ClientID clientId) noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto it = clientIdToSessions_.find(clientId);
    if (it != clientIdToSessions_.end()) {
        return it->second;
    }
    return nullptr;
}
