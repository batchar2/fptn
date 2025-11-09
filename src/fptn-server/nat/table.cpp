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

Table::Table(fptn::common::network::IPv4Address tun_ipv4,
    fptn::common::network::IPv4Address tun_ipv4_network_address,
    std::uint32_t tun_network_ipv4_mask,
    fptn::common::network::IPv6Address tun_ipv6,
    fptn::common::network::IPv6Address tun_ipv6_network_address,
    std::uint32_t tun_network_ipv6_mask)
    : client_number_(0),
      tun_ipv4_(std::move(tun_ipv4)),
      tun_ipv4_network_address_(std::move(tun_ipv4_network_address)),
      tun_network_ipv4_mask_(tun_network_ipv4_mask),
      tun_ipv6_(std::move(tun_ipv6)),
      tun_ipv6_network_address_(std::move(tun_ipv6_network_address)),
      tun_network_ipv6_mask_(tun_network_ipv6_mask),
      ipv4_generator_(tun_ipv4_network_address_, tun_network_ipv4_mask_),
      ipv6_generator_(tun_ipv6_network_address_, tun_network_ipv6_mask_) {}

fptn::client::SessionSPtr Table::CreateClientSession(ClientID client_id,
    const std::string& user_name,
    const fptn::common::network::IPv4Address& client_ipv4,
    const fptn::common::network::IPv6Address& client_ipv6,
    const fptn::traffic_shaper::LeakyBucketSPtr& to_client,
    const fptn::traffic_shaper::LeakyBucketSPtr& from_client) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (!client_id_to_sessions_.contains(client_id)) {
    if (client_number_ >= ipv4_generator_.NumAvailableAddresses()) {
      /* ||  client_number_ >= client_ipv6.NumAvailableAddresses() */
      SPDLOG_INFO("Client limit was exceeded");
      return nullptr;
    }
    client_number_ += 1;
    try {
      const auto fake_ipv4 = GetUniqueIPv4Address();
      const auto fake_ipv6 = GetUniqueIPv6Address();
      auto session = std::make_shared<fptn::client::Session>(client_id,
          user_name, client_ipv4, fake_ipv4, client_ipv6, fake_ipv6, to_client,
          from_client);
      client_id_to_sessions_.insert({client_id, session});
      ipv4_to_sessions_.insert(
          {fake_ipv4.ToInt(), session});  // ipv4 -> session
      ipv6_to_sessions_.insert(
          {fake_ipv6.ToString(), session});  // ipv6 -> session
      return session;
    } catch (const std::runtime_error& err) {
      SPDLOG_INFO("Client error: {}", err.what());
    } catch (const std::exception& e) {
      SPDLOG_ERROR(
          "Standard exception while creating client session: {}", e.what());
    } catch (...) {
      SPDLOG_ERROR("An unknown error occurred while creating client session.");
    }
  }
  return nullptr;
}

bool Table::DelClientSession(ClientID client_id) {
  fptn::client::SessionSPtr ipv4_session;
  fptn::client::SessionSPtr ipv6_session;
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    auto it = client_id_to_sessions_.find(client_id);
    if (it != client_id_to_sessions_.end()) {
      const IPv4INT ipv4_int = it->second->FakeClientIPv4().ToInt();
      const std::string ipv6_str = it->second->FakeClientIPv6().ToString();
      client_id_to_sessions_.erase(it);

      // delete ipv4 -> session
      {
        auto it_ipv4 = ipv4_to_sessions_.find(ipv4_int);
        if (it_ipv4 != ipv4_to_sessions_.end()) {
          ipv4_session = std::move(it_ipv4->second);
          ipv4_to_sessions_.erase(it_ipv4);
        }
      }
      // delete ipv6 -> session
      {
        auto it_ipv6 = ipv6_to_sessions_.find(ipv6_str);
        if (it_ipv6 != ipv6_to_sessions_.end()) {
          ipv6_session = std::move(it_ipv6->second);
          ipv6_to_sessions_.erase(it_ipv6);
        }
      }
    }
  }
  return ipv4_session != nullptr && ipv6_session != nullptr;
}

fptn::client::SessionSPtr Table::GetSessionByFakeIPv4(
    const fptn::common::network::IPv4Address& ip) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  const auto it = ipv4_to_sessions_.find(ip.ToInt());
  if (it != ipv4_to_sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::client::SessionSPtr Table::GetSessionByFakeIPv6(
    const fptn::common::network::IPv6Address& ip) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  auto it = ipv6_to_sessions_.find(ip.ToString());
  if (it != ipv6_to_sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::client::SessionSPtr Table::GetSessionByClientId(
    ClientID clientId) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  auto it = client_id_to_sessions_.find(clientId);
  if (it != client_id_to_sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

std::size_t Table::GetNumberActiveSessionByUsername(
    const std::string& username) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return std::count_if(ipv4_to_sessions_.begin(), ipv4_to_sessions_.end(),
      [&username](
          const auto& pair) { return pair.second->UserName() == username; });
}

fptn::common::network::IPv4Address Table::GetUniqueIPv4Address() {
  for (std::uint32_t i = 0; i < ipv4_generator_.NumAvailableAddresses(); i++) {
    const auto ip = ipv4_generator_.GetNextAddress();
    if (ip != tun_ipv4_ && !ipv4_to_sessions_.contains(ip.ToInt())) {
      return ip;
    }
  }
  throw std::runtime_error("No available address");
}

fptn::common::network::IPv6Address Table::GetUniqueIPv6Address() {
  for (int i = 0; i < ipv6_generator_.NumAvailableAddresses(); i++) {
    const auto ip = ipv6_generator_.GetNextAddress();
    if (ip != tun_ipv6_ && !ipv6_to_sessions_.contains(ip.ToString())) {
      return ip;
    }
  }
  throw std::runtime_error("No available address");
}

void Table::UpdateStatistic(const fptn::statistic::MetricsSPtr& prometheus) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  prometheus->UpdateActiveSessions(client_id_to_sessions_.size());
  for (const auto& client : client_id_to_sessions_) {
    auto client_id = client.first;
    const auto& session = client.second;
    prometheus->UpdateStatistics(client_id, session->UserName(),
        session->TrafficShaperToClient()->FullDataAmount(),
        session->TrafficShaperFromClient()->FullDataAmount());
  }
}
