/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/manager.h"

#include <utility>

using fptn::vpn::Manager;

Manager::Manager(fptn::web::ServerPtr web_server,
    fptn::network::VirtualInterfacePtr network_interface,
    fptn::nat::TableSPtr nat,
    fptn::filter::ManagerSPtr filter,
    fptn::statistic::MetricsSPtr prometheus)
    : web_server_(std::move(web_server)),
      network_interface_(std::move(network_interface)),
      nat_(std::move(nat)),
      filter_(std::move(filter)),
      prometheus_(std::move(prometheus)) {}

Manager::~Manager() { Stop(); }

bool Manager::Stop() noexcept {
  running_ = false;

  network_interface_->Stop();
  web_server_->Stop();

  if (read_to_client_thread_.joinable()) {
    read_to_client_thread_.join();
  }
  if (read_from_client_thread_.joinable()) {
    read_from_client_thread_.join();
  }
  if (collect_statistics_.joinable()) {
    collect_statistics_.join();
  }
  return true;
}

bool Manager::Start() noexcept {
  running_ = true;
  web_server_->Start();
  network_interface_->Start();

  read_to_client_thread_ = std::thread(&Manager::RunToClient, this);
  const bool to_status = read_to_client_thread_.joinable();

  read_from_client_thread_ = std::thread(&Manager::RunFromClient, this);
  const bool from_status = read_from_client_thread_.joinable();

  collect_statistics_ = std::thread(&Manager::RunCollectStatistics, this);
  const bool collect_statistic_status = collect_statistics_.joinable();
  return (to_status && from_status && collect_statistic_status);
}

void Manager::RunToClient() const noexcept {
  constexpr std::chrono::milliseconds kTimeout{10};

  while (running_) {
    auto packet = network_interface_->WaitForPacket(kTimeout);
    if (!packet || !running_) {
      continue;
    }
    if (!packet->IsIPv4() && !packet->IsIPv6()) {
      continue;
    }
    // get session using "fake" client address
    fptn::client::SessionSPtr session = nullptr;
    if (packet->IsIPv4()) {
      session = nat_->GetSessionByFakeIPv4(fptn::common::network::IPv4Address(
          packet->IPv4Layer()->getDstIPv4Address()));
    } else if (packet->IsIPv6()) {
      session = nat_->GetSessionByFakeIPv6(fptn::common::network::IPv6Address(
          packet->IPv6Layer()->getDstIPv6Address()));
    }
    if (!session || !running_) {
      continue;
    }
    // check shaper
    auto& shaper = session->TrafficShaperToClient();
    if (shaper && !shaper->CheckSpeedLimit(packet->Size())) {
      continue;
    }
    // send
    if (running_) {
      web_server_->Send(session->ChangeIPAddressToClientIP(std::move(packet)));
    }
  }
}

void Manager::RunFromClient() const noexcept {
  constexpr std::chrono::milliseconds kTimeout{10};

  while (running_) {
    auto packet = web_server_->WaitForPacket(kTimeout);
    if (!packet || !running_) {
      continue;
    }
    if (!packet->IsIPv4() && !packet->IsIPv6()) {
      continue;
    }
    // get session
    const auto session = nat_->GetSessionByClientId(packet->ClientId());
    if (!session || !running_) {
      continue;
    }
    // check shaper
    auto shaper = session->TrafficShaperFromClient();
    if (shaper && !shaper->CheckSpeedLimit(packet->Size())) {
      continue;
    }
    // filter
    packet = filter_->Apply(std::move(packet));
    if (!packet || !running_) {
      continue;
    }
    // send
    if (running_) {
      network_interface_->Send(
          session->ChangeIPAddressToFakeIP(std::move(packet)));
    }
  }
}

void Manager::RunCollectStatistics() noexcept {
  const std::chrono::milliseconds timeout{300};
  const std::chrono::seconds collect_interval{2};

  std::chrono::steady_clock::time_point last_collection_time;
  while (running_) {
    auto now = std::chrono::steady_clock::now();
    if (now - last_collection_time > collect_interval) {
      nat_->UpdateStatistic(prometheus_);
      last_collection_time = now;
    }
    std::this_thread::sleep_for(timeout);
  }
}
