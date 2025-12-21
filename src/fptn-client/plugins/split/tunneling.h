/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <re2/re2.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"

#include "plugins/base_plugin.h"
#include "routing/route_manager.h"

namespace fptn::plugin {
class Tunneling final : public BasePlugin {
 public:
  explicit Tunneling(const std::vector<std::string>& rules,
      routing::RouteManagerSPtr route_manager,
      fptn::routing::RoutingPolicy policy);

  ~Tunneling() override = default;

  fptn::common::network::IPPacketPtr HandlePacket(
      fptn::common::network::IPPacketPtr packet) override;

 private:
  const routing::RouteManagerSPtr route_manager_;
  const fptn::routing::RoutingPolicy policy_;


  std::vector<std::unique_ptr<RE2>> rules_;
};

using TunnelingPtr = std::unique_ptr<Tunneling>;

}  // namespace fptn::plugin
