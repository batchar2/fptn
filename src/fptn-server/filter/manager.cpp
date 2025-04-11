/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "filter/manager.h"

#include <utility>

using fptn::common::network::IPPacketPtr;
using fptn::filter::Manager;

void Manager::Add(BaseFilterSPtr filter) noexcept {
  filters_.push_back(std::move(filter));
}

IPPacketPtr Manager::Apply(IPPacketPtr packet) const {
  for (const auto& filter : filters_) {
    packet = filter->apply(std::move(packet));
    if (!packet) {
      return nullptr;  // packet was filtered
    }
  }
  return packet;
}
