#include "leaky_bucket.h"

using namespace fptn::traffic_shaper;


LeakyBucket::LeakyBucket(std::size_t maxRateBitesPerSecond) :  
    currentAmount_(0), maxRateBytesPerSecond_(maxRateBitesPerSecond/8), lastLeakTime_(std::chrono::steady_clock::now())
{
}

bool LeakyBucket::checkSpeedLimit(std::size_t packetSize) noexcept
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastLeakTime_).count();
    if (elapsed < 1000) {
        if (currentAmount_ + packetSize < maxRateBytesPerSecond_) {
            currentAmount_ += packetSize;
            return true;
        }
        return false;
    }
    lastLeakTime_ = now;
    currentAmount_ = packetSize;
    return true;
}
