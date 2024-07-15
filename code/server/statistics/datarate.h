#pragma once 

#include <chrono>
#include <iostream>


namespace fptn
{
    class datarate 
    {
    public:
        datarate() 
            : 
                data_rate_(0),
                total_data_received_(0), 
                start_time_(std::chrono::steady_clock::now()) 
        {
        }

        void add_data(const std::string &data) noexcept
        {
            std::lock_guard<std::mutex> lock(mtx_);

            total_data_received_ += data.size();
            auto now = std::chrono::steady_clock::now();
            std::chrono::duration<double> elapsed = now - start_time_;

            if (elapsed.count() >= 1.0) {  // Каждую секунду
                data_rate_ = total_data_received_ / elapsed.count();
                total_data_received_ = 0;
                start_time_ = now;
            }
        }
        const double data_rate() const 
        {
            return data_rate_;
        }
    private:
        std::mutex mtx_;
        double data_rate_;
        std::uint64_t total_data_received_;
        std::chrono::steady_clock::time_point start_time_;
    };  
} 
