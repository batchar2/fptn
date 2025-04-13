/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <mutex>

#include "common/network/ip_packet.h"

namespace fptn::traffic_shaper {
class LeakyBucket final {
 public:
  explicit LeakyBucket(std::size_t max_bites_per_second);
  bool CheckSpeedLimit(std::size_t packet_size) noexcept;
  std::size_t FullDataAmount() const noexcept;

 private:
  mutable std::mutex mutex_;
  std::size_t current_amount_;
  std::size_t max_bytes_per_second;
  std::chrono::steady_clock::time_point last_leak_time_;

  std::size_t full_data_amount_;
};

using LeakyBucketSPtr = std::shared_ptr<LeakyBucket>;
}  // namespace fptn::traffic_shaper
