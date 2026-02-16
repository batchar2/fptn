/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "nat/table.h"

#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace {

fptn::nat::ConnectionMultiplexerSPtr GetMultiplexerBySessionId(
    const fptn::nat::NatMultiplexers& multiplexers,
    const std::string& session_id) {
  if (multiplexers.contains(session_id)) {
    return multiplexers.at(session_id);
  }
  return nullptr;
}

fptn::nat::ConnectionMultiplexerSPtr GetMultiplexerByClientId(
    const fptn::nat::NatMultiplexers& multiplexers,
    const fptn::ClientID& client_id) {
  const auto it =
      std::ranges::find_if(multiplexers, [&client_id](const auto& pair) {
        const auto& multiplexer = pair.second;
        return multiplexer && multiplexer->HasClientId(client_id);
      });
  if (it != multiplexers.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::nat::ConnectionMultiplexerSPtr GetMultiplexerByFakeIPv4(
    const fptn::nat::NatMultiplexers& multiplexers,
    const fptn::common::network::IPv4Address& ip) {
  const auto it = std::ranges::find_if(multiplexers, [&ip](const auto& pair) {
    const auto& multiplexer = pair.second;
    return multiplexer && multiplexer->FakeClientIPv4() == ip;
  });
  if (it != multiplexers.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::nat::ConnectionMultiplexerSPtr GetMultiplexerByFakeIPv6(
    const fptn::nat::NatMultiplexers& multiplexers,
    const fptn::common::network::IPv6Address& ip) {
  const auto it = std::ranges::find_if(multiplexers, [&ip](const auto& pair) {
    const auto& multiplexer = pair.second;
    return multiplexer && multiplexer->FakeClientIPv6() == ip;
  });
  if (it != multiplexers.end()) {
    return it->second;
  }
  return nullptr;
}

std::size_t GetNumberActiveSessionByUsername(
    const fptn::nat::NatMultiplexers& multiplexers,
    const std::string& username) {
  std::size_t number = 0;
  for (const auto& [session_id, multiplexer] : multiplexers) {
    if (multiplexer->Username() == username) {
      ++number;
    }
  }
  return number;
}

}  // namespace

namespace fptn::nat {

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

ConnectionMultiplexerSPtr Table::AddConnection(
    const fptn::nat::ConnectParams& params) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (client_number_ >= ipv4_generator_.NumAvailableAddresses()) {
    SPDLOG_INFO("Client limit was exceeded");
    return nullptr;
  }

  if (auto mplx =
          GetMultiplexerBySessionId(multiplexers_, params.request.session_id)) {
    if (mplx->AddClientConnection(params)) {
      multiplexers_.insert({params.request.session_id, mplx});
      return mplx;
    }
    return nullptr;
  }

  const auto fake_ipv4_opt = GetUniqueIPv4Address();
  const auto fake_ipv6_opt = GetUniqueIPv6Address();
  if (!fake_ipv4_opt.has_value() || !fake_ipv6_opt.has_value()) {
    return nullptr;
  }

  const auto& fake_ipv4 = fake_ipv4_opt.value();
  const auto& fake_ipv6 = fake_ipv6_opt.value();

  auto mplx = ConnectionMultiplexer::Create(params, fake_ipv4, fake_ipv6);

  // DO NOT REMOVE
  // session_id_to_connections_.insert({params.request.session_id, mplx});
  // ipv4_to_mplxs_.insert({fake_ipv4.ToInt(), mplx});     // ipv4 -> session
  // ipv6_to_mplxs_.insert({fake_ipv6.ToString(), mplx});  // ipv6 -> session

  multiplexers_.insert({params.request.session_id, mplx});

  client_number_ += 1;

  return mplx;
}

bool Table::DelConnectionByClientId(ClientID client_id) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);

  auto multiplexer = GetMultiplexerByClientId(multiplexers_, client_id);
  if (multiplexer == nullptr) {
    return false;
  }

  multiplexer->DelConnectionByClientId(client_id);

  if (multiplexer->Size() == 0) {
    return multiplexers_.erase(multiplexer->SessionId()) > 0;
  }
  return true;
}

fptn::nat::ConnectionMultiplexerSPtr Table::GetConnectionMultiplexerByFakeIPv4(
    const fptn::common::network::IPv4Address& ip) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return ::GetMultiplexerByFakeIPv4(multiplexers_, ip);
}

fptn::nat::ConnectionMultiplexerSPtr Table::GetConnectionMultiplexerByFakeIPv6(
    const fptn::common::network::IPv6Address& ip) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return ::GetMultiplexerByFakeIPv6(multiplexers_, ip);
}

fptn::nat::ConnectionMultiplexerSPtr Table::GetConnectionMultiplexerByClientId(
    ClientID clientId) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return ::GetMultiplexerByClientId(multiplexers_, clientId);
}

std::size_t Table::GetNumberActiveSessionByUsername(
    const std::string& username) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return ::GetNumberActiveSessionByUsername(multiplexers_, username);
}

std::optional<IPv4Address> Table::GetUniqueIPv4Address() noexcept {
  for (std::uint32_t i = 0; i < ipv4_generator_.NumAvailableAddresses(); i++) {
    auto ip = ipv4_generator_.GetNextAddress();
    if (ip != tun_ipv4_ && GetMultiplexerByFakeIPv4(multiplexers_, ip)) {
      return ip;
    }
  }
  return std::nullopt;
}

std::optional<IPv6Address> Table::GetUniqueIPv6Address() noexcept {
  for (int i = 0; i < ipv6_generator_.NumAvailableAddresses(); i++) {
    auto ip = ipv6_generator_.GetNextAddress();
    if (ip != tun_ipv6_ && !GetMultiplexerByFakeIPv6(multiplexers_, ip)) {
      return ip;
    }
  }
  return std::nullopt;
}

void Table::UpdateStatistic(
    const fptn::statistic::MetricsSPtr& prometheus) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  (void)prometheus;
  //
  // prometheus->UpdateActiveSessions(client_id_to_mplxs_.size());
  // for (const auto& client : client_id_to_mplxs_) {
  //   auto client_id = client.first;
  //   const auto& session = client.second;
  //   prometheus->UpdateStatistics(client_id, session->UserName(),
  //       session->TrafficShaperToClient()->FullDataAmount(),
  //       session->TrafficShaperFromClient()->FullDataAmount());
  // }
}
}  // namespace fptn::nat