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

VirtualInterface::VirtualInterface(
    fptn::common::network::TunInterface::Config config,
    fptn::routing::RouteManagerPtr iptables)
    : running_(false), iptables_(std::move(iptables)) {
  // NOLINTNEXTLINE(modernize-avoid-bind)
  auto callback = std::bind(
      &VirtualInterface::IPPacketFromNetwork, this, std::placeholders::_1);
  virtual_network_interface_ =
      std::make_unique<TunInterface>(std::move(config));
  virtual_network_interface_->SetRecvIPPacketCallback(callback);
}

VirtualInterface::~VirtualInterface() { Stop(); }

bool VirtualInterface::Check() noexcept { return thread_.joinable(); }

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
  try {
    to_network_.Push(std::move(packet));
  } catch (const std::bad_alloc& err) {
    SPDLOG_ERROR(
        "Memory allocation failed while sending packet: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred while sending packet.");
  }
}

fptn::common::network::IPPacketPtr VirtualInterface::WaitForPacket(
    const std::chrono::milliseconds& duration) noexcept {
  return from_network_.WaitForPacket(duration);
}

void VirtualInterface::Run() noexcept {
  const auto timeout = std::chrono::milliseconds(300);

  iptables_->Apply();  // activate route
  while (running_) {
    auto packet = to_network_.WaitForPacket(timeout);
    if (packet != nullptr) {
      virtual_network_interface_->Send(std::move(packet));
    }
  }
}

void VirtualInterface::IPPacketFromNetwork(
    fptn::common::network::IPPacketPtr packet) noexcept {
  from_network_.Push(std::move(packet));
}
