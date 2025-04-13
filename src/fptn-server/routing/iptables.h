/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <mutex>
#include <string>

namespace fptn::routing {
class IPTables final {
 public:
  IPTables(
      std::string out_net_interface_name, std::string tun_net_interface_name);
  ~IPTables();
  bool Apply();
  bool Clean();

 private:
  mutable std::mutex mutex_;

  const std::string out_net_interface_name_;
  const std::string tun_net_interface_name_;

  bool running_;
};

using IPTablesPtr = std::unique_ptr<IPTables>;
}  // namespace fptn::routing
