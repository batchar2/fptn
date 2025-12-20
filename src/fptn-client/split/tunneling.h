/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <regex>
#include <string>
#include <vector>

#include "common/network/ip_packet.h"

#include "route/route_manager.h"

namespace fptn::split {
class Tunneling final {
 public:
  explicit Tunneling(
      const std::vector<std::string>& rules, RouteManagerPtr route_manager);

  fptn::common::network::IPPacketPtr HandlePacket(
      fptn::common::network::IPPacketPtr packet) const;

 protected:
  bool MatchDomain(const std::string& domain) const;

 private:
  const RouteManagerPtr route_manager_;

  std::vector<std::regex> rules_;
};

using TunnelingPtr = std::unique_ptr<Tunneling>;

}  // namespace fptn::split
