/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <utility>
#include <vector>

#include <blockingconcurrentqueue.h>  // NOLINT(build/include_order)
#include <spdlog/spdlog.h>            // NOLINT(build/include_order)

#include "common/network/ip_packet.h"

namespace fptn::common::data {

class Channel {
 public:
  explicit Channel(std::size_t max_capacity = 1024)
      : max_capacity_(max_capacity), capacity_(0), buffer_(max_capacity) {}

  bool Push(network::IPPacketPtr pkt) noexcept {
    if (capacity_.load(std::memory_order_relaxed) < max_capacity_) {
      buffer_.enqueue(std::move(pkt));
      capacity_.fetch_add(1, std::memory_order_relaxed);
      return true;
    }
    return false;
  }

  network::IPPacketPtr WaitForPacket(
      const std::chrono::milliseconds& duration) noexcept {
    network::IPPacketPtr packet;

    if (buffer_.try_dequeue(packet) && packet != nullptr) {
      capacity_.fetch_sub(1, std::memory_order_relaxed);
      return packet;
    }

    if (buffer_.wait_dequeue_timed(packet, duration) && packet != nullptr) {
      capacity_.fetch_sub(1, std::memory_order_relaxed);
    }
    return packet;
  }

  network::BatchIPPacketPtr TryGetPackets(
      const std::size_t max_batch_size = 16) noexcept {
    network::BatchIPPacketPtr batch;
    batch.resize(max_batch_size);

    const auto count = buffer_.try_dequeue_bulk(batch.data(), max_batch_size);
    if (count > 0) {
      batch.resize(count);
      capacity_.fetch_sub(count, std::memory_order_relaxed);
      return batch;
    }
    batch.clear();
    return batch;
  }

  network::BatchIPPacketPtr WaitForPackets(
      const std::chrono::milliseconds& duration,
      const std::size_t max_batch_size = 64) noexcept {
    network::BatchIPPacketPtr batch(max_batch_size);
    // batch.resize(max_batch_size);

    std::cerr << "  READ +1" << std::endl;
    const auto count = buffer_.try_dequeue_bulk(batch.data(), max_batch_size);
    std::cerr << "  READ +2" << std::endl;
    if (count > 0) {
      std::cerr << "  READ +4" << std::endl;
      batch.resize(count);
      std::cerr << "  READ +4" << std::endl;
      capacity_.fetch_sub(count, std::memory_order_relaxed);
      std::cerr << "  READ +5" << std::endl;
      return batch;
    }
    std::cerr << "  READ +6" << std::endl;
    batch.clear();
    std::cerr << "  READ +7" << std::endl;

    network::IPPacketPtr packet;
    std::cerr << "  READ +8" << std::endl;
    if (buffer_.wait_dequeue_timed(packet, duration) && packet != nullptr) {
      std::cerr << "  READ +9" << std::endl;
      capacity_.fetch_sub(1, std::memory_order_relaxed);
      std::cerr << "  READ +10" << std::endl;
      batch.push_back(std::move(packet));
    }
    std::cerr << "  READ +11" << std::endl;
    return batch;
  }

 private:
  const std::size_t max_capacity_;
  std::atomic<std::size_t> capacity_;
  moodycamel::BlockingConcurrentQueue<network::IPPacketPtr> buffer_;
};

using ChannelPtr = std::unique_ptr<Channel>;

}  // namespace fptn::common::data
