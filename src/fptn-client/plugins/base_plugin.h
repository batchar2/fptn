/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <vector>

#include "common/network/ip_packet.h"

namespace fptn::plugin {
class BasePlugin {
 public:
  virtual ~BasePlugin() = default;
  virtual fptn::common::network::IPPacketPtr HandlePacket(
      fptn::common::network::IPPacketPtr packet) = 0;
};

using BasePluginPtr = std::unique_ptr<BasePlugin>;
using PluginList = std::vector<BasePluginPtr>;

}  // namespace fptn::plugin
