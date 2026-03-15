/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/circular_buffer/space_optimized.hpp>

#include "common/network/ip_packet.h"

namespace fptn::common::data {
namespace this_coro = boost::asio::this_coro;
using boost::asio::use_awaitable;

class ChannelAsync {
 public:
  // Increased defaults for high throughput
  explicit ChannelAsync(boost::asio::io_context& ioc)
      : ioc_(ioc) {
    // Capacity 8192
    buffer_.set_capacity(8192);
  }
  void Push(network::IPPacketPtr pkt) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);
      if (buffer_.size() < buffer_.capacity()) {
          buffer_.push_back(std::move(pkt));
      }
    }
    condvar_.notify_one();
    
    // Trigger async waiter if any
    if (timer_) {
        timer_->cancel();
    }
  }

  network::IPPacketPtr WaitForPacket(
      const std::chrono::milliseconds& duration) {
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

  boost::asio::awaitable<std::optional<network::IPPacketPtr>>
  WaitForPacketAsync() {
    // Optimistic check without creating timer
    {
      const std::unique_lock<std::mutex> lock(mutex_);
      if (!buffer_.empty()) {
        auto pkt = std::move(buffer_.front());
        buffer_.pop_front();
        co_return pkt;
      }
    }

    // Wait for notification or timeout (e.g. 50ms to batch)
    try {
        timer_ = std::make_unique<boost::asio::steady_timer>(ioc_);
        timer_->expires_after(std::chrono::milliseconds(50));
        co_await timer_->async_wait(boost::asio::use_awaitable);
    } catch (...) {
        // Timer cancelled means data arrived
    }
    
    // Check again
    {
      const std::unique_lock<std::mutex> lock(mutex_);
      if (!buffer_.empty()) {
        auto pkt = std::move(buffer_.front());
        buffer_.pop_front();
        co_return pkt;
      }
    }
    co_return std::nullopt;
  }

 protected:
  boost::asio::io_context& ioc_;
  std::unique_ptr<boost::asio::steady_timer> timer_;

  mutable std::mutex mutex_;
  std::condition_variable condvar_;

  boost::circular_buffer_space_optimized<network::IPPacketPtr> buffer_;
};

using ChannelAsyncPtr = std::unique_ptr<ChannelAsync>;
}  // namespace fptn::common::data
