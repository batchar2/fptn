/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <memory>
#include <thread>

#include "filter/manager.h"
#include "nat/table.h"
#include "network/virtual_interface.h"
#include "web/server.h"

namespace fptn::vpn {
class Manager final {
 public:
  Manager(fptn::web::ServerPtr web_server,
      fptn::network::VirtualInterfacePtr network_interface,
      fptn::nat::TableSPtr nat,
      fptn::filter::ManagerSPtr filter,
      fptn::statistic::MetricsSPtr prometheus);
  ~Manager();
  bool Stop() noexcept;
  bool Start() noexcept;

 private:
  void RunToClient() noexcept;
  void RunFromClient() noexcept;
  void RunCollectStatistics() noexcept;

 private:
  std::atomic<bool> running_ = false;

  const fptn::web::ServerPtr web_server_;
  const fptn::network::VirtualInterfacePtr network_interface_;
  const fptn::nat::TableSPtr nat_;
  const fptn::filter::ManagerSPtr filter_;
  const fptn::statistic::MetricsSPtr prometheus_;

  std::thread read_to_client_thread_;
  std::thread read_from_client_thread_;
  std::thread collect_statistics_;
};

using UserManagerSPtr = std::shared_ptr<fptn::user::UserManager>;
}  // namespace fptn::vpn
