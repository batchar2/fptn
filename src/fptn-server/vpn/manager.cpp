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
    fptn::statistic::MetricsSPtr prometheus,
    std::size_t thread_pool_size)
    : web_server_(std::move(web_server)),
      network_interface_(std::move(network_interface)),
      nat_(std::move(nat)),
      filter_(std::move(filter)),
      prometheus_(std::move(prometheus)),
      thread_pool_size_(thread_pool_size > 0 ? thread_pool_size : 1) {
  read_to_client_threads_.reserve(thread_pool_size_);
  read_from_client_threads_.reserve(thread_pool_size_);
}

Manager::~Manager() { Stop(); }

bool Manager::Stop() {
  running_ = false;

  network_interface_->Stop();
  web_server_->Stop();

  for (auto& thread : read_to_client_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  read_to_client_threads_.clear();

  for (auto& thread : read_from_client_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  read_from_client_threads_.clear();

  if (collect_statistics_.joinable()) {
    collect_statistics_.join();
  }
  return true;
}

bool Manager::Start() {
  running_ = true;
  web_server_->Start();
  network_interface_->Start();

  for (size_t i = 0; i < thread_pool_size_; ++i) {
    read_to_client_threads_.emplace_back(
        &Manager::RunProcessingToWebsocket, this);
  }

  for (size_t i = 0; i < thread_pool_size_; ++i) {
    read_from_client_threads_.emplace_back(
        &Manager::RunProcessingFromWebsocket, this);
  }

  collect_statistics_ = std::thread(&Manager::RunCollectStatistics, this);
  const bool collect_statistic_status = collect_statistics_.joinable();
  return collect_statistic_status;
}

void Manager::RunProcessingToWebsocket() const noexcept {
  constexpr std::chrono::milliseconds kTimeout{100};

  while (running_) {
    auto packet = network_interface_->WaitForPacket(kTimeout);
    if (!packet || !running_) {
      continue;
    }

    fptn::nat::ConnectionMultiplexerSPtr connection_multiplexer = nullptr;
    if (packet->IsIPv4()) {
      connection_multiplexer =
          nat_->GetConnectionMultiplexerByFakeIPv4(packet->DstIPv4Address());
    } else if (packet->IsIPv6()) {
      connection_multiplexer =
          nat_->GetConnectionMultiplexerByFakeIPv6(packet->DstIPv6Address());
    }

    if (!connection_multiplexer || !running_) {
      continue;
    }

    packet =
        connection_multiplexer->PacketPreparingToWebsocket(std::move(packet));
    if (packet && running_) {
      web_server_->Send(std::move(packet));
    }
  }
}

void Manager::RunProcessingFromWebsocket() const noexcept {
  constexpr std::chrono::milliseconds kTimeout{100};

  while (running_) {
    auto packet = web_server_->WaitForPacket(kTimeout);
    if (!packet || !running_) {
      continue;
    }
    if (!packet->IsIPv4() && !packet->IsIPv6()) {
      continue;
    }

    const auto connection_multiplexer =
        nat_->GetConnectionMultiplexerByClientId(packet->ClientId());
    if (!connection_multiplexer || !running_) {
      continue;
    }

    packet =
        connection_multiplexer->PacketPreparingFromWebsocket(std::move(packet));
    if (packet && running_) {
      network_interface_->Send(std::move(packet));
    }
  }
}

void Manager::RunCollectStatistics() noexcept {
  constexpr std::chrono::milliseconds kTimeout{300};
  constexpr std::chrono::seconds kCollectInterval{10};

  std::chrono::steady_clock::time_point last_collection_time;
  while (running_) {
    auto now = std::chrono::steady_clock::now();
    if (now - last_collection_time > kCollectInterval) {
      nat_->UpdateStatistic(prometheus_);
      last_collection_time = now;
    }
    std::this_thread::sleep_for(kTimeout);
  }
}
