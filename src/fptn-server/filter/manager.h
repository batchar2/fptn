/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <vector>

#include "common/network/ip_packet.h"

#include "filters/base_filter.h"

namespace fptn::filter {

class Manager {
 public:
  Manager() = default;
  void Add(BaseFilterSPtr filter) noexcept;

  [[nodiscard]] fptn::common::network::IPPacketPtr Apply(
      fptn::common::network::IPPacketPtr packet) const;

 private:
  std::vector<BaseFilterSPtr> filters_;
};

using ManagerSPtr = std::shared_ptr<Manager>;
}  // namespace fptn::filter
