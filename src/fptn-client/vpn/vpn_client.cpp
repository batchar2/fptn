/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/vpn_client.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::vpn {

VpnClient::VpnClient(
    fptn::protocol::connection::ConnectionManagerPtr connectin_manager,
    fptn::common::network::TunInterfacePtr virtual_net_interface,
    fptn::plugin::PluginList plugins,
    std::size_t thread_pool_size)
    : running_(false),
      connectin_manager_(std::move(connectin_manager)),
      virtual_net_interface_(std::move(virtual_net_interface)),
      plugins_(std::move(plugins)),
      thread_pool_size_(thread_pool_size) {
  // NOLINTNEXTLINE(modernize-avoid-bind)
  connectin_manager_->SetRecvIPPacketCallback(std::bind(
      &VpnClient::HandlePacketFromWebSocket, this, std::placeholders::_1));

  virtual_net_interface_->SetRecvIPPacketCallback(
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&VpnClient::HandlePacketFromVirtualNetworkInterface, this,
          std::placeholders::_1));
}

VpnClient::~VpnClient() { Stop(); }

bool VpnClient::IsStarted() const {
  if (!running_) {
    return false;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return running_ && connectin_manager_ && connectin_manager_->IsStarted();
}

bool VpnClient::Start() {
  if (running_) {
    return false;
  }

  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (running_) {
      return false;
    }
  }

  connectin_manager_->Start();
  virtual_net_interface_->Start();
  running_ = true;

  // Start workers
  worker_threads_.reserve(thread_pool_size_);
  for (std::size_t i = 0; i < thread_pool_size_; ++i) {
    worker_threads_.emplace_back(&VpnClient::ProcessWebSocketPackets, this);
  }

  return true;
}

bool VpnClient::Stop() {
  if (!running_) {
    return false;
  }
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (!running_) {
      return false;
    }

    running_ = false;
  }

  ws_queue_cv_.notify_all();

  SPDLOG_INFO("Stopping VPN Websocket-workers...");

  for (auto& thread : worker_threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
  worker_threads_.clear();

  SPDLOG_INFO("Stopping VPN client...");

  if (virtual_net_interface_) {
    SPDLOG_INFO("Stopping virtual network interface");
    virtual_net_interface_->Stop();
    virtual_net_interface_.reset();
    SPDLOG_DEBUG("Virtual network interface stopped successfully");
  }

  if (connectin_manager_) {
    SPDLOG_INFO("Stopping HTTP client");
    connectin_manager_->Stop();
    connectin_manager_.reset();
    SPDLOG_DEBUG("HTTP client stopped successfully");
  }
  return true;
}

std::size_t VpnClient::GetSendRate() {
  if (!running_) {
    return 0;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (running_ && virtual_net_interface_) {
    return virtual_net_interface_->GetSendRate();
  }
  return 0;
}

std::size_t VpnClient::GetReceiveRate() {
  if (!running_) {
    return 0;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (running_ && virtual_net_interface_) {
    return virtual_net_interface_->GetReceiveRate();
  }
  return 0;
}

void VpnClient::HandlePacketFromVirtualNetworkInterface(
    fptn::common::network::IPPacketPtr packet) {
  if (!running_) {
    return;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (running_ && connectin_manager_) {
    connectin_manager_->Send(std::move(packet));
  }
}

void VpnClient::HandlePacketFromWebSocket(
    fptn::common::network::IPPacketPtr packet) {
  if (!running_ || !packet) {
    return;
  }

  constexpr std::size_t kMaxQueueSize = 128;

  std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (ws_packet_queue_.size() >= kMaxQueueSize) {
    SPDLOG_WARN("WebSocket packet queue is full, dropping packet");
    return;
  }

  ws_packet_queue_.push(std::move(packet));
  lock.unlock();
  ws_queue_cv_.notify_one();
}

void VpnClient::ProcessWebSocketPackets() {
  fptn::common::network::IPPacketPtr packet;
  while (running_) {
    {
      std::unique_lock<std::mutex> lock(mutex_);  // mutex

      if (ws_packet_queue_.empty()) {
        ws_queue_cv_.wait(
            lock, [this]() { return !ws_packet_queue_.empty() || !running_; });
      }
      if (!running_ && ws_packet_queue_.empty()) {
        break;
      }
      if (!ws_packet_queue_.empty()) {
        packet = std::move(ws_packet_queue_.front());
        ws_packet_queue_.pop();
      }
    }

    if (!packet) {
      continue;
    }

    if (running_ && !plugins_.empty()) {
      for (const auto& plugin : plugins_) {
        if (packet) {
          auto [processed_packet, triggered] =
              plugin->HandlePacket(std::move(packet));
          packet = std::move(processed_packet);
          if (triggered) {
            break;
          }
        }
      }
    }

    if (running_ && packet) {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex
      if (running_ && virtual_net_interface_) {
        virtual_net_interface_->Send(std::move(packet));
      }
    }
  }
}
}  // namespace fptn::vpn
