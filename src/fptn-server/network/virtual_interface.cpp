/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "network/virtual_interface.h"

#include <memory>
#include <string>
#include <utility>

using fptn::common::network::TunInterface;
using fptn::network::VirtualInterface;

VirtualInterface::VirtualInterface(const std::string& name,
    fptn::common::network::TunInterface::Config config,
    fptn::routing::RouteManagerPtr iptables)
    : running_(false),
      name_(name),
      config_(std::move(config)),
      iptables_(std::move(iptables)) {
  // NOLINTNEXTLINE(modernize-avoid-bind)
  const auto callback = std::bind(
      &VirtualInterface::IPPacketFromNetwork, this, std::placeholders::_1);
  virtual_network_interface_ = std::make_unique<TunInterface>(name, false);
  virtual_network_interface_->SetRecvIPPacketCallback(callback);
}

VirtualInterface::~VirtualInterface() { Stop(); }

bool VirtualInterface::Check() noexcept { return thread_.joinable(); }

bool VirtualInterface::Start() noexcept {
  running_ = true;
  virtual_network_interface_->Start(config_);
  iptables_->Apply();  // activate route
  return true;
}

bool VirtualInterface::Stop() noexcept {
  running_ = false;
  virtual_network_interface_->Stop();
  iptables_->Clean();
  return true;
}

void VirtualInterface::Send(
    fptn::common::network::IPPacketPtr packet) noexcept {
  virtual_network_interface_->Send(std::move(packet));
}

fptn::common::network::BatchIPPacketPtr VirtualInterface::WaitForPackets(
    const std::chrono::milliseconds& duration) noexcept {
  return from_network_.WaitForPackets(duration);
}

void VirtualInterface::IPPacketFromNetwork(
    fptn::common::network::IPPacketPtr packet) noexcept {
  from_network_.Push(std::move(packet));
}
