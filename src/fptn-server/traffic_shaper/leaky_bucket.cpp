/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "traffic_shaper/leaky_bucket.h"

using fptn::traffic_shaper::LeakyBucket;

LeakyBucket::LeakyBucket(std::size_t max_bites_per_second)
    : current_amount_(0),
      max_bytes_per_second(max_bites_per_second / 8),
      last_leak_time_(std::chrono::steady_clock::now()),
      full_data_amount_(0) {}

std::size_t LeakyBucket::FullDataAmount() const noexcept {
  return full_data_amount_;
}

bool LeakyBucket::CheckSpeedLimit(std::size_t packetSize) noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);

  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - last_leak_time_)
                     .count();
  if (elapsed < 1000) {
    if (current_amount_ + packetSize < max_bytes_per_second) {
      current_amount_ += packetSize;
      full_data_amount_ += packetSize;
      return true;
    }
    return false;
  }
  last_leak_time_ = now;
  current_amount_ = packetSize;
  return true;
}
