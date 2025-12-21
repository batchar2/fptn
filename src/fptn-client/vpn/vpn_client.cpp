/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/vpn_client.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>

using fptn::vpn::VpnClient;

VpnClient::VpnClient(fptn::vpn::http::ClientPtr http_client,
    fptn::common::network::TunInterfacePtr virtual_net_interface,
    fptn::common::network::IPv4Address dns_server_ipv4,
    fptn::common::network::IPv6Address dns_server_ipv6,
    fptn::plugin::PluginList plugins)
    : running_(false),
      http_client_(std::move(http_client)),
      virtual_net_interface_(std::move(virtual_net_interface)),
      dns_server_ipv4_(std::move(dns_server_ipv4)),
      dns_server_ipv6_(std::move(dns_server_ipv6)),
      plugins_(std::move(plugins)) {}

VpnClient::~VpnClient() { Stop(); }

bool VpnClient::IsStarted() {
  if (!running_) {
    return false;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return running_ && http_client_ && http_client_->IsStarted();
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

  // NOLINTNEXTLINE(modernize-avoid-bind)
  http_client_->SetRecvIPPacketCallback(std::bind(
      &VpnClient::HandlePacketFromWebSocket, this, std::placeholders::_1));

  virtual_net_interface_->SetRecvIPPacketCallback(
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&VpnClient::HandlePacketFromVirtualNetworkInterface, this,
          std::placeholders::_1));

  http_client_->Start();
  virtual_net_interface_->Start();
  running_ = true;
  return true;
}

bool VpnClient::Stop() {
  if (!running_) {
    return false;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // cppcheck-suppress identicalConditionAfterEarlyExit
  if (!running_) {
    return false;
  }

  running_ = false;

  SPDLOG_INFO("Stopping VPN client...");

  if (virtual_net_interface_) {
    SPDLOG_INFO("Stopping virtual network interface");
    virtual_net_interface_->Stop();
    virtual_net_interface_.reset();
    SPDLOG_DEBUG("Virtual network interface stopped successfully");
  }

  if (http_client_) {
    SPDLOG_INFO("Stopping HTTP client");
    http_client_->Stop();
    http_client_.reset();
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

  if (running_ && http_client_) {
    http_client_->Send(std::move(packet));
  }
}

void VpnClient::HandlePacketFromWebSocket(
    fptn::common::network::IPPacketPtr packet) {
  if (!running_) {
    return;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (running_) {
    // run plugins
    if (!plugins_.empty() && packet) {
      for (const auto& plugin : plugins_) {
        if (packet) {
          packet = plugin->HandlePacket(std::move(packet));
        }
      }
    }
    if (virtual_net_interface_ && packet) {
      virtual_net_interface_->Send(std::move(packet));
    }
  }
}
