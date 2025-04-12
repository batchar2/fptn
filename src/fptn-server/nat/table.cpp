/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "nat/table.h"

#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

using fptn::nat::Table;

Table::Table(const pcpp::IPv4Address& tun_ipv4,
    const pcpp::IPv4Address& tun_ipv4_network_address,
    std::uint32_t tun_network_ipv4_mask,
    const pcpp::IPv6Address& tun_ipv6,
    const pcpp::IPv6Address& tun_ipv6_network_address,
    std::uint32_t tun_network_ipv6_mask)
    : client_number_(0),
      tun_ipv4_(tun_ipv4),
      tun_ipv6_(tun_ipv6),
      ipv4_generator_(tun_ipv4_network_address, tun_network_ipv4_mask),
      ipv6_generator_(tun_ipv6_network_address, tun_network_ipv6_mask) {}

fptn::client::SessionSPtr Table::CreateClientSession(ClientID clientId,
    const std::string& userName,
    const pcpp::IPv4Address& clientIPv4,
    const pcpp::IPv6Address& clientIPv6,
    const fptn::traffic_shaper::LeakyBucketSPtr& trafficShaperToClient,
    const fptn::traffic_shaper::LeakyBucketSPtr&
        trafficShaperFromClient) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);

  if (client_id_to_sessions_.find(clientId) == client_id_to_sessions_.end()) {
    if (client_number_ >= ipv4_generator_.NumAvailableAddresses()) {
      /* ||  clientNumber_ >= ipv6Generator_.numAvailableAddresses() */
      SPDLOG_INFO("Client limit was exceeded");
      return nullptr;
    }
    client_number_ += 1;
    try {
      const auto fakeIPv4 = GetUniqueIPv4Address();
      const auto fakeIPv6 = GetUniqueIPv6Address();
      auto session = std::make_shared<fptn::client::Session>(clientId, userName,
          clientIPv4, fakeIPv4, clientIPv6, fakeIPv6, trafficShaperToClient,
          trafficShaperFromClient);
      client_id_to_sessions_.insert({clientId, session});
      ipv4_to_sessions_.insert({fakeIPv4.toInt(), session});  // ipv4 -> session
      ipv6_to_sessions_.insert(
          {fakeIPv6.toString(), session});  // ipv6 -> session
      return session;
    } catch (const std::runtime_error& err) {
      SPDLOG_INFO("Client error: {}", err.what());
    }
  }
  return nullptr;
}

bool Table::DelClientSession(ClientID clientId) noexcept {
  fptn::client::SessionSPtr ipv4Session;
  fptn::client::SessionSPtr ipv6Session;
  {
    const std::unique_lock<std::mutex> lock(mutex_);

    auto it = client_id_to_sessions_.find(clientId);
    if (it != client_id_to_sessions_.end()) {
      const IPv4INT ipv4Int = it->second->FakeClientIPv4().toInt();
      const std::string ipv6Str = it->second->FakeClientIPv6().toString();
      client_id_to_sessions_.erase(it);

      // delete ipv4 -> session
      {
        auto it_ipv4 = ipv4_to_sessions_.find(ipv4Int);
        if (it_ipv4 != ipv4_to_sessions_.end()) {
          ipv4Session = std::move(it_ipv4->second);
          ipv4_to_sessions_.erase(it_ipv4);
        }
      }
      // delete ipv6 -> session
      {
        auto it_ipv6 = ipv6_to_sessions_.find(ipv6Str);
        if (it_ipv6 != ipv6_to_sessions_.end()) {
          ipv6Session = std::move(it_ipv6->second);
          ipv6_to_sessions_.erase(it_ipv6);
        }
      }
    }
  }
  return ipv4Session != nullptr && ipv6Session != nullptr;
}

fptn::client::SessionSPtr Table::GetSessionByFakeIPv4(
    const pcpp::IPv4Address& ip) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);

  auto it = ipv4_to_sessions_.find(ip.toInt());
  if (it != ipv4_to_sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::client::SessionSPtr Table::GetSessionByFakeIPv6(
    const pcpp::IPv6Address& ip) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);

  auto it = ipv6_to_sessions_.find(ip.toString());
  if (it != ipv6_to_sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::client::SessionSPtr Table::GetSessionByClientId(
    ClientID clientId) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);

  auto it = client_id_to_sessions_.find(clientId);
  if (it != client_id_to_sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

pcpp::IPv4Address Table::GetUniqueIPv4Address() {
  for (std::uint32_t i = 0; i < ipv4_generator_.NumAvailableAddresses(); i++) {
    const auto ip = ipv4_generator_.GetNextAddress();
    if (ip != tun_ipv4_ &&
        ipv4_to_sessions_.find(ip.toInt()) == ipv4_to_sessions_.end()) {
      return ip;
    }
  }
  throw std::runtime_error("No available address");
}

pcpp::IPv6Address Table::GetUniqueIPv6Address() {
  for (int i = 0; i < ipv6_generator_.NumAvailableAddresses(); i++) {
    const auto ip = ipv6_generator_.GetNextAddress();
    if (ip != tun_ipv6_ &&
        ipv6_to_sessions_.find(ip.toString()) == ipv6_to_sessions_.end()) {
      return ip;
    }
  }
  throw std::runtime_error("No available address");
}

void Table::UpdateStatistic(
    const fptn::statistic::MetricsSPtr& prometheus) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);

  prometheus->UpdateActiveSessions(client_id_to_sessions_.size());
  for (const auto& client : client_id_to_sessions_) {
    auto clientID = client.first;
    auto& session = client.second;
    prometheus->UpdateStatistics(clientID, session->UserName(),
        session->TrafficShaperToClient()->FullDataAmount(),
        session->TrafficShaperFromClient()->FullDataAmount());
  }
}
