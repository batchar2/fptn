/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>

#include <openssl/base.h>  // NOLINT(build/include_order)

#include <queue>

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

#include "fptn-protocol-lib/connection/connection_manager/connection_manager.h"
#include "plugins/split/tunneling.h"

namespace fptn::vpn {
class VpnClient final {
 public:
  explicit VpnClient(
      fptn::protocol::connection::ConnectionManagerPtr connectin_manager,
      fptn::common::network::TunInterfacePtr virtual_net_interface,
      fptn::plugin::PluginList plugins,
      std::size_t thread_pool_size = 4);
  ~VpnClient();
  bool Start();
  bool Stop();
  std::size_t GetSendRate();
  std::size_t GetReceiveRate();
  bool IsStarted() const;

 protected:
  void HandlePacketFromVirtualNetworkInterface(
      fptn::common::network::IPPacketPtr packet);
  void HandlePacketFromWebSocket(fptn::common::network::IPPacketPtr packet);

  void ProcessWebSocketPackets();

 private:
  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  fptn::protocol::connection::ConnectionManagerPtr connectin_manager_;
  fptn::common::network::TunInterfacePtr virtual_net_interface_;
  const fptn::plugin::PluginList plugins_;

  const std::size_t thread_pool_size_;
  std::vector<std::thread> worker_threads_;
  std::condition_variable ws_queue_cv_;
  std::queue<fptn::common::network::IPPacketPtr> ws_packet_queue_;
};

using VpnClientPtr = std::unique_ptr<fptn::vpn::VpnClient>;
}  // namespace fptn::vpn
