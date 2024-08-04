#pragma once 

#include <mutex>
#include <chrono>
#include <memory>

#include <common/network/ip_packet.h>


namespace fptn::traffic_shaper
{
    class LeakyBucket final
    {
    public:
        LeakyBucket(std::size_t maxRateBitesPerSecond);
        bool checkSpeedLimit(std::size_t packetSize) noexcept;
    private:
        mutable std::mutex mutex_;
        std::size_t currentAmount_;
        std::size_t maxRateBytesPerSecond_;
        std::chrono::steady_clock::time_point lastLeakTime_;
    };

    using LeakyBucketSPtr = std::shared_ptr<LeakyBucket>;
}
