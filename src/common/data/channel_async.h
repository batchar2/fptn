#pragma once

#include <mutex>
#include <atomic>
#include <future>
#include <thread>
#include <memory>
#include <chrono>
#include <optional>
#include <condition_variable>

#include <boost/circular_buffer.hpp>
#include <boost/circular_buffer/space_optimized.hpp>

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/experimental/parallel_group.hpp>

#include <common/network/ip_packet.h>


namespace fptn::common::data
{
    namespace this_coro = boost::asio::this_coro;
    using boost::asio::use_awaitable;

    class ChannelAsync
    {
    public:
        explicit ChannelAsync(boost::asio::io_context& ioc, std::size_t maxCapacity=512, std::size_t threadPoolSize=4)
                : ioc_(ioc), pool_(threadPoolSize)
        {
            buffer_.set_capacity(maxCapacity);
        }
        void push(network::IPPacketPtr pkt)
        {
            {
                const std::unique_lock<std::mutex> lock(mutex_);
                buffer_.push_back(std::move(pkt));
            }
            condvar_.notify_one();
        }

        network::IPPacketPtr waitForPacket(const std::chrono::milliseconds& duration)
        {
            std::unique_lock<std::mutex> lock(mutex_);

            // exists
            if (!buffer_.empty()) {
                auto pkt = std::move(buffer_.front());
                buffer_.pop_front();
                return pkt;
            }
            // wait for data or timeout
            if (condvar_.wait_for(lock, duration, [this]{ return !buffer_.empty(); })) {
                auto pkt = std::move(buffer_.front());
                buffer_.pop_front();
                return pkt;
            }
            return nullptr;
        }

        boost::asio::awaitable<std::optional<network::IPPacketPtr>> waitForPacketAsync(const std::chrono::milliseconds& duration)
        {
            {
                std::unique_lock<std::mutex> lock(mutex_);

                // exists
                if (!buffer_.empty()) {
                    auto pkt = std::move(buffer_.front());
                    buffer_.pop_front();
                    co_return pkt;
                }
            }

            // wait for timeout
            co_await asyncWaitUntil(duration);

            {
                std::unique_lock<std::mutex> lock(mutex_);

                if (!buffer_.empty()) {
                    auto pkt = std::move(buffer_.front());
                    buffer_.pop_front();
                    co_return pkt;
                }
            }
            co_return std::nullopt;
        }

        boost::asio::awaitable<void> asyncWaitUntil(const std::chrono::steady_clock::duration &timeout)
        {
            boost::asio::steady_timer timer(ioc_, timeout);

            co_await timer.async_wait(boost::asio::use_awaitable);
            /*
            // Get the current coroutine's executor.
            auto executor = co_await boost::asio::this_coro::executor;
            auto buffer = &buffer_;
            // Use async_initiate to create an awaitable asynchronous operation.
            co_await boost::asio::async_initiate<decltype(boost::asio::use_awaitable),
                void(boost::system::error_code)>(
                // The initiating lambda captures references to cv, lock and the duration.
                [&cv, &lock, &duration, executor, buffer](auto &&handler) mutable {
                    // Post a lambda to the executor (or to a thread pool if you have one)
                    boost::asio::post(executor, [&, handler = std::move(handler)]() mutable {
                        // Perform the blocking wait in the background thread.
                        cv.wait_for(lock, duration, [] { return !buffer_->empty(); });
                        // Invoke the completion handler with a default error_code (i.e. success)
                        handler(boost::system::error_code{});
                        }
                    );
                },
                boost::asio::use_awaitable
            );
            */
            co_return;
        }
    protected:
        boost::asio::io_context& ioc_;
        boost::asio::thread_pool pool_;

        std::mutex mutex_;  ///< Mutex for synchronizing access to the buffer.
        std::condition_variable condvar_;  ///< Condition variable for notifying about available packets.

        boost::circular_buffer_space_optimized<network::IPPacketPtr> buffer_;  ///< Buffer for storing packets.
    };

    using ChannelAsyncPtr = std::unique_ptr<ChannelAsync>;
}
