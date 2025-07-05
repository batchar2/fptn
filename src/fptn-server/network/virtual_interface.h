/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <thread>

#include "common/data/channel.h"
#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

#include "routing/iptables.h"

namespace fptn::network {

class VirtualInterface final {
 public:
  VirtualInterface(fptn::common::network::TunInterface::Config config,
      fptn::routing::IPTablesPtr iptables);
  ~VirtualInterface();

  bool Check() noexcept;
  bool Start() noexcept;
  bool Stop() noexcept;
  void Send(fptn::common::network::IPPacketPtr packet) noexcept;
  fptn::common::network::IPPacketPtr WaitForPacket(
      const std::chrono::milliseconds& duration) noexcept;

 protected:
  void Run() noexcept;
  void IPPacketFromNetwork(fptn::common::network::IPPacketPtr packet) noexcept;

 private:
  std::thread thread_;
  std::atomic<bool> running_;

  const fptn::routing::IPTablesPtr iptables_;

  fptn::common::data::Channel to_network_;
  fptn::common::data::Channel from_network_;
  fptn::common::network::TunInterfacePtr virtual_network_interface_;
};

using VirtualInterfacePtr = std::unique_ptr<VirtualInterface>;
}  // namespace fptn::network
