/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <blockingconcurrentqueue.h>
#include <chrono>
#include <memory>
#include <utility>

#include "common/network/ip_packet.h"

namespace fptn::common::data {
class Channel {
 public:
  // Increase default capacity for high throughput
  explicit Channel(std::size_t max_capacity = 8192)
      : max_capacity_(max_capacity), buffer_(max_capacity) {}

  void Push(network::IPPacketPtr pkt) noexcept {
    if (buffer_.size_approx() < max_capacity_) {
      buffer_.enqueue(std::move(pkt));
      ++capacity_;
    }
  }

  network::IPPacketPtr WaitForPacket(
      const std::chrono::milliseconds& duration) noexcept {
    network::IPPacketPtr pkt;

    if (buffer_.try_dequeue(pkt) && pkt != nullptr) {
      --capacity_;
      return pkt;
    }
    if (buffer_.wait_dequeue_timed(pkt, duration) && pkt != nullptr) {
      --capacity_;
      return pkt;
    }
    return nullptr;
  }

  network::BatchIPPacketPtr WaitForPackets(
      const std::chrono::milliseconds& duration,
      const std::size_t max_batch_size = 64) noexcept {
    std::vector<network::IPPacketPtr> batch;
    batch.reserve(max_batch_size);

    network::IPPacketPtr pkt;
    if (buffer_.wait_dequeue_timed(pkt, duration) && pkt != nullptr) {
      --capacity_;
      batch.push_back(std::move(pkt));
    } else {
      return batch;
    }

    for (std::size_t i = 1; i < max_batch_size; ++i) {
      if (buffer_.try_dequeue(pkt) && pkt != nullptr) {
        --capacity_;
        batch.push_back(std::move(pkt));
      } else {
        break;
      }
    }

    return batch;
  }

 private:
  const std::size_t max_capacity_;

  std::atomic<std::size_t> capacity_;
  moodycamel::BlockingConcurrentQueue<network::IPPacketPtr> buffer_;
};

using ChannelPtr = std::unique_ptr<Channel>;
}  // namespace fptn::common::data
