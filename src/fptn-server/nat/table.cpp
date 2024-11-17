#include "table.h"

#include <spdlog/spdlog.h>


using namespace fptn::nat;


Table::Table(const pcpp::IPv4Address& tunInterfaceIP,
      const pcpp::IPv4Address& tunInterfaceNetworkAddress,
      std::uint32_t tunInterfaceNetworkMask)
      :
        clientNumber_(0),
        tunInterfaceIP_(tunInterfaceIP),
        ipGenerator_(tunInterfaceNetworkAddress, tunInterfaceNetworkMask)
{
}

fptn::client::SessionSPtr Table::createClientSession(ClientID clientId,
    const std::string& userName,
    const pcpp::IPv4Address& clientIP,
    const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperToClient,
    const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperFromClient) noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (clientIdToSessions_.find(clientId) == clientIdToSessions_.end()) {
        if (clientNumber_ < ipGenerator_.numAvailableAddresses()) {
            clientNumber_ += 1;
            try {
                auto fakeIP = getUniqueIPAddress();
                auto session = std::make_shared<fptn::client::Session>(
                    clientId,
                    userName,
                    clientIP,
                    fakeIP,
                    trafficShaperToClient,
                    trafficShaperFromClient
                );
                ipToSessions_.insert({fakeIP.toInt(), session});
                clientIdToSessions_.insert({clientId, session});
                return session;
            } catch(const std::runtime_error& err) {
                spdlog::info("Client error: {}", err.what());
            }
        } else {
            spdlog::info("Client limit ({}) was exceeded", ipGenerator_.numAvailableAddresses());
        }
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
                clientNumber_ -= 1;
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

pcpp::IPv4Address Table::getUniqueIPAddress()
{
    for (int i = 0; i < ipGenerator_.numAvailableAddresses(); i++) {
        const auto ip = ipGenerator_.getNextAddress();
        if (ip != tunInterfaceIP_ && ipToSessions_.find(ip.toInt()) == ipToSessions_.end()) {
            return ip;
        }
    }
    throw std::runtime_error("No available address");
}

void Table::updateStatistic(fptn::statistic::MetricsSPtr& prometheus) noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);

    prometheus->updateActiveSessions(clientIdToSessions_.size());
    for (const auto &client: clientIdToSessions_) {
        auto clientID = client.first;
        auto& session = client.second;
        prometheus->updateStatistics(
                clientID,
                session->userName(),
                session->getTrafficShaperToClient()->fullDataAmount(),
                session->getTrafficShaperFromClient()->fullDataAmount()
        );
    }
}
