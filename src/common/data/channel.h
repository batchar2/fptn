#pragma once

#include <mutex>
#include <atomic>
#include <thread>
#include <memory>
#include <chrono>
#include <condition_variable>

#include <boost/circular_buffer.hpp>
#include <boost/circular_buffer/space_optimized.hpp>

#include <common/network/ip_packet.h>

namespace fptn::common::data
{

    class Channel
    {
    public:
        Channel(std::size_t max_capacity = 512)
        {
            buffer_.set_capacity(max_capacity);
        }
        void push(network::IPPacketPtr pkt)
        {
            {
                std::unique_lock<std::mutex> lock(mutex_);
                buffer_.push_back(std::move(pkt));
            }
            condvar_.notify_one();
        }

        network::IPPacketPtr waitForPacket(const std::chrono::milliseconds& duration) 
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (condvar_.wait_for(lock, duration, [this]{ return !buffer_.empty(); })) {
                auto pkt = std::move(buffer_.front());
                buffer_.pop_front();
                return pkt;
            }
            return nullptr;
        }
    private:
        std::mutex mutex_;  ///< Mutex for synchronizing access to the buffer.
        std::condition_variable condvar_;  ///< Condition variable for notifying about available packets.
        boost::circular_buffer_space_optimized<network::IPPacketPtr> buffer_;  ///< Buffer for storing packets.
    };
}
