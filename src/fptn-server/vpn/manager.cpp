/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/manager.h"

#include <utility>

using fptn::vpn::Manager;

Manager::Manager(fptn::web::ServerPtr web_server,
    fptn::network::VirtualInterfacePtr network_interface,
    const fptn::nat::TableSPtr& nat,
    const fptn::filter::ManagerSPtr& filter,
    const fptn::statistic::MetricsSPtr& prometheus)
    : web_server_(std::move(web_server)),
      network_interface_(std::move(network_interface)),
      nat_(nat),
      filter_(filter),
      prometheus_(prometheus) {}

Manager::~Manager() { Stop(); }

bool Manager::Stop() noexcept {
  running_ = false;
  if (read_to_client_thread_.joinable()) {
    read_to_client_thread_.join();
  }
  if (read_from_client_thread_.joinable()) {
    read_from_client_thread_.join();
  }
  if (collect_statistics_.joinable()) {
    collect_statistics_.join();
  }
  return (web_server_->Stop() && network_interface_->Stop());
}

bool Manager::Start() noexcept {
  running_ = true;
  web_server_->Start();
  network_interface_->Start();

  read_to_client_thread_ = std::thread(&Manager::RunToClient, this);
  bool toStatus = read_to_client_thread_.joinable();

  read_from_client_thread_ = std::thread(&Manager::RunFromClient, this);
  bool fromStatus = read_from_client_thread_.joinable();

  collect_statistics_ = std::thread(&Manager::RunCollectStatistics, this);
  bool collectStatisticStatus = collect_statistics_.joinable();
  return (toStatus && fromStatus && collectStatisticStatus);
}

void Manager::RunToClient() noexcept {
  constexpr std::chrono::milliseconds timeout{30};

  while (running_) {
    auto packet = network_interface_->WaitForPacket(timeout);
    if (!packet) {
      continue;
    }
    if (!packet->IsIPv4() && !packet->IsIPv6()) {
      continue;
    }
    // get session using "fake" client address
    auto session =
        (packet->IsIPv4()
                ? nat_->GetSessionByFakeIPv4(
                      packet->IPv4Layer()->getDstIPv4Address())
                : (packet->IsIPv6()
                          ? nat_->GetSessionByFakeIPv6(
                                packet->IPv6Layer()->getDstIPv6Address())
                          : nullptr));
    if (!session) {
      continue;
    }
    // check shaper
    auto& shaper = session->TrafficShaperToClient();
    if (shaper && !shaper->CheckSpeedLimit(packet->Size())) {
      continue;
    }
    // send
    web_server_->Send(session->ChangeIPAddressToClientIP(std::move(packet)));
  }
}

void Manager::RunFromClient() noexcept {
  constexpr std::chrono::milliseconds timeout{30};

  while (running_) {
    auto packet = web_server_->WaitForPacket(timeout);
    if (!packet) {
      continue;
    }
    if (!packet->IsIPv4() && !packet->IsIPv6()) {
      continue;
    }
    // get session
    auto session = nat_->GetSessionByClientId(packet->ClientId());
    if (!session) {
      continue;
    }
    // check shaper
    auto shaper = session->TrafficShaperFromClient();
    if (shaper && !shaper->CheckSpeedLimit(packet->Size())) {
      continue;
    }
    // filter
    packet = filter_->Apply(std::move(packet));
    if (!packet) {
      continue;
    }
    // send
    network_interface_->Send(
        session->ChangeIPAddressToFakeIP(std::move(packet)));
  }
}

void Manager::RunCollectStatistics() noexcept {
  constexpr std::chrono::milliseconds timeout{300};
  constexpr std::chrono::seconds collectInterval{2};

  std::chrono::steady_clock::time_point lastCollectionTime;
  while (running_) {
    auto now = std::chrono::steady_clock::now();
    if (now - lastCollectionTime > collectInterval) {
      nat_->UpdateStatistic(prometheus_);
      lastCollectionTime = now;
    }
    std::this_thread::sleep_for(timeout);
  }
}
