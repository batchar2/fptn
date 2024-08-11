#include "table.h"

#include <glog/logging.h>

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
                                                     const pcpp::IPv4Address& clientIP,
                                                     fptn::traffic_shaper::LeakyBucketSPtr trafficShaper) noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (clientIdToSessions_.find(clientId) == clientIdToSessions_.end()) {
        if (clientNumber_ < ipGenerator_.numAvailableAddresses()) {
            clientNumber_ += 1;
            try {
                auto fakeIP = getUniqueIPAddress();
                auto session = std::make_shared<fptn::client::Session>(
                        clientId,
                        clientIP,
                        fakeIP,
                        std::move(trafficShaper));
                ipToSessions_.insert({fakeIP.toInt(), session});
                clientIdToSessions_.insert({clientId, session});
                return session;
            } catch(const std::runtime_error& err) {
                LOG(ERROR) << "Client error: " << err.what();
            }
        } else {
            LOG(ERROR) << "Client limit (" << ipGenerator_.numAvailableAddresses() << ") was exceeded";
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
