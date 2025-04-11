/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "network/virtual_interface.h"

#include <memory>
#include <string>
#include <utility>

using fptn::common::network::TunInterface;
using fptn::network::VirtualInterface;

VirtualInterface::VirtualInterface(const std::string& name,
    const pcpp::IPv4Address& ipv4Address,
    const int ipv4Netmask,
    const pcpp::IPv6Address& ipv6Address,
    const int ipv6Netmask,
    fptn::routing::IPTablesPtr iptables)
    : running_(false), iptables_(std::move(iptables)) {
  auto callback = std::bind(
      &VirtualInterface::IPPacketFromNetwork, this, std::placeholders::_1);
  virtual_network_interface_ = std::make_unique<TunInterface>(
      name, ipv4Address, ipv4Netmask, ipv6Address, ipv6Netmask, callback);
}

VirtualInterface::~VirtualInterface() { Stop(); }

bool VirtualInterface::Check() noexcept { return true; }

bool VirtualInterface::Start() noexcept {
  running_ = true;
  virtual_network_interface_->Start();
  thread_ = std::thread(&VirtualInterface::Run, this);
  return thread_.joinable();
}

bool VirtualInterface::Stop() noexcept {
  running_ = false;
  virtual_network_interface_->Stop();
  if (thread_.joinable()) {
    iptables_->Clean();
    thread_.join();
    return true;
  }
  return false;
}

void VirtualInterface::Send(
    fptn::common::network::IPPacketPtr packet) noexcept {
  to_network_.push(std::move(packet));
}

fptn::common::network::IPPacketPtr VirtualInterface::WaitForPacket(
    const std::chrono::milliseconds& duration) noexcept {
  return from_network_.waitForPacket(duration);
}

void VirtualInterface::Run() noexcept {
  const auto timeout = std::chrono::milliseconds(300);

  iptables_->Apply();  // activate route
  while (running_) {
    auto packet = to_network_.waitForPacket(timeout);
    if (packet != nullptr) {
      virtual_network_interface_->Send(std::move(packet));
    }
  }
}

void VirtualInterface::IPPacketFromNetwork(
    fptn::common::network::IPPacketPtr packet) noexcept {
  from_network_.push(std::move(packet));
}
