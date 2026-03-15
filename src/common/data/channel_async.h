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
  explicit ChannelAsync(
      boost::asio::io_context& ioc, const std::size_t max_capacity = 8192)
      : ioc_(ioc), notify_timer_(ioc) {
    buffer_.set_capacity(max_capacity);
    notify_timer_.expires_at(std::chrono::steady_clock::time_point::max());
  }

  void Push(network::IPPacketPtr pkt) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);
      if (buffer_.size() < buffer_.capacity()) {
        buffer_.push_back(std::move(pkt));
      }
    }
    try {
      condvar_.notify_one();
      notify_timer_.cancel();  // Trigger async waiter if any
    } catch (...) {
      SPDLOG_WARN("ChannelAsync::Push unexpected exception: ");
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
  WaitForPacketAsync(std::chrono::milliseconds timeout) {
    {
      const std::lock_guard<std::mutex> lock(mutex_);  // mutex
      if (!buffer_.empty()) {
        auto pkt = std::move(buffer_.front());
        buffer_.pop_front();
        co_return pkt;
      }
    }

    boost::asio::steady_timer timeout_timer(ioc_);
    timeout_timer.expires_after(timeout);

    boost::asio::steady_timer local_notify_timer(ioc_);
    local_notify_timer.expires_at(std::chrono::steady_clock::time_point::max());
    {
      std::unique_lock<std::mutex> lock(mutex_);  // mutex

      if (!buffer_.empty()) {
        auto pkt = std::move(buffer_.front());
        buffer_.pop_front();
        co_return pkt;
      }
      lock.unlock();

      co_await boost::asio::experimental::make_parallel_group(
          timeout_timer.async_wait(boost::asio::deferred),
          local_notify_timer.async_wait(boost::asio::deferred))
          .async_wait(
              boost::asio::experimental::wait_for_one(), boost::asio::deferred);
    }

    {
      const std::lock_guard<std::mutex> lock(mutex_);  // mutex
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
  mutable boost::asio::steady_timer notify_timer_;

  mutable std::mutex mutex_;
  std::condition_variable condvar_;

  boost::circular_buffer_space_optimized<network::IPPacketPtr> buffer_;
};

using ChannelAsyncPtr = std::unique_ptr<ChannelAsync>;
}  // namespace fptn::common::data
