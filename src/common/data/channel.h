/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>

#include <boost/circular_buffer.hpp>
#include <boost/circular_buffer/space_optimized.hpp>

#include "common/network/ip_packet.h"

namespace fptn::common::data {
class Channel {
 public:
  explicit Channel(std::size_t maxCapacity = 512) {
    buffer_.set_capacity(maxCapacity);
  }
  void Push(network::IPPacketPtr pkt) noexcept {
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      buffer_.push_back(std::move(pkt));
    }
    condvar_.notify_one();
  }

  network::IPPacketPtr WaitForPacket(
      const std::chrono::milliseconds& duration) noexcept {
    std::unique_lock<std::mutex> lock(mutex_);  // mutex

    // exists
    if (!buffer_.empty()) {
      auto pkt = std::move(buffer_.front());
      buffer_.pop_front();
      return pkt;
    }
    // wait for data or timeout
    if (condvar_.wait_for(
            lock, duration, [this] { return !buffer_.empty(); })) {
      auto pkt = std::move(buffer_.front());
      buffer_.pop_front();
      return pkt;
    }
    return nullptr;
  }

 protected:
  mutable std::mutex mutex_;
  std::condition_variable condvar_;
  boost::circular_buffer_space_optimized<network::IPPacketPtr> buffer_;
};

using ChannelPtr = std::unique_ptr<Channel>;
}  // namespace fptn::common::data
