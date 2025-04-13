/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>

#include "common/network/ip_packet.h"

namespace fptn::filter {

class BaseFilter {
 public:
  BaseFilter() = default;
  virtual fptn::common::network::IPPacketPtr apply(
      fptn::common::network::IPPacketPtr packet) const noexcept = 0;
  ~BaseFilter() = default;
};

using BaseFilterSPtr = std::shared_ptr<BaseFilter>;
}  // namespace fptn::filter
