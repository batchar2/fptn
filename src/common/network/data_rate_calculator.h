/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <chrono>
#include <mutex>

namespace fptn::common::network {
class DataRateCalculator {
 public:
  explicit DataRateCalculator(
      std::chrono::milliseconds interval = std::chrono::milliseconds(1000))
      : interval_(interval),
        bytes_(0),
        last_update_time_(std::chrono::steady_clock::now()),
        rate_(0) {}
  void Update(std::size_t len) noexcept {
    const std::scoped_lock lock(mutex_);  // mutex

    const auto now = std::chrono::steady_clock::now();
    const std::chrono::duration<double> elapsed = now - last_update_time_;
    bytes_ += len;
    if (elapsed >= interval_) {
      rate_ = static_cast<std::size_t>(bytes_ / elapsed.count());
      last_update_time_ = now;
      bytes_ = 0;
    }
  }
  std::size_t GetRateForSecond() const noexcept {
    const std::scoped_lock lock(mutex_);  // mutex

    const auto interval_count = interval_.count();
    if (interval_count) {
      return static_cast<std::size_t>(rate_ / (1000 / interval_.count()));
    }
    return 0;
  }

 private:
  mutable std::mutex mutex_;
  std::chrono::milliseconds interval_;
  std::atomic<std::size_t> bytes_;
  std::chrono::steady_clock::time_point last_update_time_;
  std::atomic<std::size_t> rate_;
};

}  // namespace fptn::common::network
