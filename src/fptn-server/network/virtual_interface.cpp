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
    int mtu_size,
    fptn::routing::RouteManagerPtr route_manager,
    fptn::common::network::TunInterface::Config config)
    : running_(false),
      name_(name),
      mtu_size_(mtu_size),
      route_manager_(std::move(route_manager)),
      config_(std::move(config)) {
  const auto callback = [this](auto&& pkt) {
    VirtualInterface::IPPacketFromNetwork(std::forward<decltype(pkt)>(pkt));
  };
  virtual_network_interface_ =
      std::make_unique<TunInterface>(name, mtu_size_, false);
  virtual_network_interface_->SetRecvIPPacketCallback(callback);
}

VirtualInterface::~VirtualInterface() { Stop(); }

bool VirtualInterface::Check() const noexcept { return thread_.joinable(); }

bool VirtualInterface::Start() noexcept {
  running_ = true;
  virtual_network_interface_->Start(config_);
  route_manager_->Apply();  // activate route
  return true;
}

bool VirtualInterface::Stop() noexcept {
  running_ = false;
  virtual_network_interface_->Stop();
  route_manager_->Clean();
  return true;
}

void VirtualInterface::Send(
    fptn::common::network::IPPacketPtr packet) noexcept {
  virtual_network_interface_->Send(std::move(packet));
}

void VirtualInterface::SendBatch(
    const fptn::common::network::BatchIPPacketPtr& packets) noexcept {
  virtual_network_interface_->SendBatch(packets);
}

fptn::common::network::BatchIPPacketPtr VirtualInterface::WaitForPackets(
    const std::chrono::milliseconds& duration) noexcept {
  return from_network_.WaitForPackets(duration);
}

void VirtualInterface::IPPacketFromNetwork(
    fptn::common::network::IPPacketPtr packet) noexcept {
  from_network_.Push(std::move(packet));
}
