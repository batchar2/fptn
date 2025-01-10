#include "table.h"

#include <spdlog/spdlog.h>


using namespace fptn::nat;


Table::Table(const pcpp::IPv4Address& tunInterfaceIPv4,
    const pcpp::IPv4Address& tunInterfaceIPv4NetworkAddress,
    const std::uint32_t tunInterfaceNetworkIPv4Mask,
    const pcpp::IPv6Address& tunInterfaceIPv6,
    const pcpp::IPv6Address& tunInterfaceIPv6NetworkAddress,
    const std::uint32_t tunInterfaceNetworkIPv6Mask
)
    :
        clientNumber_(0),
        tunInterfaceIPv4_(tunInterfaceIPv4),
        tunInterfaceIPv6_(tunInterfaceIPv6),
        ipv4Generator_(tunInterfaceIPv4NetworkAddress, tunInterfaceNetworkIPv4Mask),
        ipv6Generator_(tunInterfaceIPv6NetworkAddress, tunInterfaceNetworkIPv6Mask)
{
}

fptn::client::SessionSPtr Table::createClientSession(ClientID clientId,
    const std::string& userName,
    const pcpp::IPv4Address& clientIPv4,
    const pcpp::IPv6Address& clientIPv6,
    const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperToClient,
    const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperFromClient) noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    if (clientIdToSessions_.find(clientId) == clientIdToSessions_.end()) {
        if (clientNumber_ >= ipv4Generator_.numAvailableAddresses() /* ||  clientNumber_ >= ipv6Generator_.numAvailableAddresses() */) {
            spdlog::info("Client limit was exceeded");
            return nullptr;
        }
        clientNumber_ += 1;
        try {
            const auto fakeIPv4 = getUniqueIPv4Address();
            const auto fakeIPv6 = getUniqueIPv6Address();
            auto session = std::make_shared<fptn::client::Session>(
                clientId,
                userName,
                clientIPv4,
                fakeIPv4,
                clientIPv6,
                fakeIPv6,
                trafficShaperToClient,
                trafficShaperFromClient
            );
            clientIdToSessions_.insert({clientId, session});
            ipv4ToSessions_.insert({fakeIPv4.toInt(), session}); // ipv4 -> session
            ipv6ToSessions_.insert({fakeIPv6.toString(), session}); // ipv6 -> session
            return session;
        } catch(const std::runtime_error& err) {
            spdlog::info("Client error: {}", err.what());
        }
    }
    return nullptr;
}

bool Table::delClientSession(ClientID clientId) noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    auto it = clientIdToSessions_.find(clientId);
    if (it != clientIdToSessions_.end()) {
        const IPv4INT ipv4Int = it->second->fakeClientIPv4().toInt();
        const std::string ipv6Str = it->second->fakeClientIPv6().toString();
        clientIdToSessions_.erase(it);
        // delete ipv4 -> session
        {
            auto it_ipv4 = ipv4ToSessions_.find(ipv4Int);
            if (it_ipv4 != ipv4ToSessions_.end()) {
                ipv4ToSessions_.erase(it_ipv4);
                clientNumber_ -= 1;
                return true;
            }
        }
        // delete ipv6 -> session
        {
            auto it_ipv6 = ipv6ToSessions_.find(ipv6Str);
            if (it_ipv6 != ipv6ToSessions_.end()) {
                ipv6ToSessions_.erase(it_ipv6);
            }
        }
    }
    return false;
}

fptn::client::SessionSPtr Table::getSessionByFakeIPv4(const pcpp::IPv4Address& ip) noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    auto it = ipv4ToSessions_.find(ip.toInt());
    if (it != ipv4ToSessions_.end()) {
        return it->second;
    }
    return nullptr;
}

fptn::client::SessionSPtr Table::getSessionByFakeIPv6(const pcpp::IPv6Address& ip) noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    auto it = ipv6ToSessions_.find(ip.toString());
    if (it != ipv6ToSessions_.end()) {
        return it->second;
    }
    return nullptr;
}

fptn::client::SessionSPtr Table::getSessionByClientId(ClientID clientId) noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    auto it = clientIdToSessions_.find(clientId);
    if (it != clientIdToSessions_.end()) {
        return it->second;
    }
    return nullptr;
}

pcpp::IPv4Address Table::getUniqueIPv4Address()
{
    for (std::uint32_t i = 0; i < ipv4Generator_.numAvailableAddresses(); i++) {
        const auto ip = ipv4Generator_.getNextAddress();
        if (ip != tunInterfaceIPv4_ && ipv4ToSessions_.find(ip.toInt()) == ipv4ToSessions_.end()) {
            return ip;
        }
    }
    throw std::runtime_error("No available address");
}

pcpp::IPv6Address Table::getUniqueIPv6Address()
{
    for (int i = 0; i < ipv6Generator_.numAvailableAddresses(); i++) {
        const auto ip = ipv6Generator_.getNextAddress();
        if (ip != tunInterfaceIPv6_ && ipv6ToSessions_.find(ip.toString()) == ipv6ToSessions_.end()) {
            return ip;
        }
    }
    throw std::runtime_error("No available address");
}

void Table::updateStatistic(fptn::statistic::MetricsSPtr& prometheus) noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

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
