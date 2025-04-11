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
  explicit ChannelAsync(boost::asio::io_context& ioc,
      std::size_t maxCapacity = 512,
      std::size_t threadPoolSize = 4)
      : ioc_(ioc), pool_(threadPoolSize) {
    buffer_.set_capacity(maxCapacity);
  }
  void Push(network::IPPacketPtr pkt) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);
      buffer_.push_back(std::move(pkt));
    }
    condvar_.notify_one();
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
  WaitForPacketAsync(const std::chrono::milliseconds& duration) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      // exists
      if (!buffer_.empty()) {
        auto pkt = std::move(buffer_.front());
        buffer_.pop_front();
        co_return pkt;
      }
    }

    // wait for timeout
    co_await AsyncWaitUntil(duration);

    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      if (!buffer_.empty()) {
        auto pkt = std::move(buffer_.front());
        buffer_.pop_front();
        co_return pkt;
      }
    }
    co_return std::nullopt;
  }

  boost::asio::awaitable<void> AsyncWaitUntil(
      const std::chrono::steady_clock::duration& timeout) {
    boost::asio::steady_timer timer(ioc_, timeout);

    co_await timer.async_wait(boost::asio::use_awaitable);

    // while (!mutex_.try_lock()) {
    //     if (std::chrono::steady_clock::now() - start >
    //     std::chrono::seconds(3)) {
    //         spdlog::error("Session::send: failed to acquire lock within
    //         timeout"); co_return false;
    //     }
    //     std::this_thread::yield();  // Yield to avoid busy waiting
    // }

    co_return;
  }

 protected:
  boost::asio::io_context& ioc_;
  boost::asio::thread_pool pool_;

  mutable std::mutex mutex_;
  std::condition_variable condvar_;

  boost::circular_buffer_space_optimized<network::IPPacketPtr> buffer_;
};

using ChannelAsyncPtr = std::unique_ptr<ChannelAsync>;
}  // namespace fptn::common::data
