/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include "filter/filters/base_filter.h"

namespace fptn::filter {
class BitTorrent : public BaseFilter {
 public:
  BitTorrent() = default;
  virtual ~BitTorrent() = default;
  fptn::common::network::IPPacketPtr apply(
      fptn::common::network::IPPacketPtr packet) const noexcept override;
};
}  // namespace fptn::filter
