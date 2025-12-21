/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <regex>
#include <string>
#include <vector>

#include <re2/re2.h>  // NOLINT(build/include_order)

#include "plugins/base_plugin.h"

namespace fptn::plugin {
class DomainBlacklist final : public BasePlugin {
 public:
  explicit DomainBlacklist(const std::vector<std::string>& rules);

  ~DomainBlacklist() override = default;

  fptn::common::network::IPPacketPtr HandlePacket(
      fptn::common::network::IPPacketPtr packet) override;

 private:
  std::vector<std::unique_ptr<RE2>> rules_;
};

using DomainBlacklistPtr = std::unique_ptr<DomainBlacklist>;

}  // namespace fptn::plugin
