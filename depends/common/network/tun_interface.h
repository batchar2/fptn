#pragma once

#include <queue>
#include <mutex>
#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <functional>

#include <tuntap++.hh>
#include <glog/logging.h>


#include <common/data/channel.h>

#include "ip_packet.h"


namespace fptn::common::network
{

    class DataRateCalculator
    {
    public:
        DataRateCalculator(std::chrono::milliseconds interval = std::chrono::milliseconds(1000))
                : interval_(interval),
                  bytes_(0),
                  lastUpdateTime_(std::chrono::steady_clock::now()),
                  rate_(0)
        {
        }
        void update(std::size_t len) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto now = std::chrono::steady_clock::now();
            std::chrono::duration<double> elapsed = now - lastUpdateTime_;
            bytes_ += len;
            if (elapsed >= interval_) {
                rate_ = static_cast<std::size_t>(bytes_ / elapsed.count());
                lastUpdateTime_ = now;
                bytes_ = 0;
            }
        }
        std::size_t getRateForSecond() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return static_cast<std::size_t>(rate_ / (1000 / interval_.count()));;
        }
    private:
        mutable std::mutex mutex_;
        std::chrono::milliseconds interval_;
        std::atomic<std::size_t> bytes_;
        std::chrono::steady_clock::time_point lastUpdateTime_;
        std::atomic<std::size_t> rate_;
    };


    using NewIPPacketCallback = std::function<void(IPPacketPtr packet)>;

    class TunInterface
    {
    public:
        TunInterface(
            const std::string& name,
            const pcpp::IPv4Address& addr,
            const int netmask, 
            const NewIPPacketCallback& callback = nullptr
        )
            : 
                mtu_(1500),
                running_(false),
                name_(name),
                addr_(addr),
                netmask_(netmask),
                newIPPktCallback_(callback)
        {
        }
        void setNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept
        {
            newIPPktCallback_ = callback;
        }
        bool start() noexcept
        {
            try {
                tun_ = std::make_unique<tuntap::tun>();
                tun_->name(name_);
                tun_->ip(addr_.toString(), netmask_);
                tun_->mtu(mtu_);
                tun_->up();
                running_ = true;
                thread_ = std::thread(&TunInterface::run, this);
                return thread_.joinable();
            } catch (const std::exception& ex) {
                LOG(ERROR) << "Error start: " << ex.what() << std::endl;
            }
            return false;
        }
        bool stop() noexcept
        {
            running_ = false;
            if (thread_.joinable()) {
                thread_.join();
                tun_->down();
                return true;
            }
            return false;
        }
        bool send(IPPacketPtr packet)
        {
            sendRateCalculator_.update(packet->size()); // calculate rate
            std::vector<std::uint8_t> serialized = packet->serialize();
            return tun_->write(serialized.data(), serialized.size()) == serialized.size();
        }
        std::size_t getSendRate() const noexcept
        {
            return sendRateCalculator_.getRateForSecond();
        }
        std::size_t getReceiveRate() const noexcept
        {
            return receiveRateCalculator_.getRateForSecond();
        }
    private:
        void run() noexcept
        {
            std::uint8_t buffer[65536] = {0};
            while(running_) {
                std::memset(buffer, 0, mtu_ + 1);
                int size = tun_->read((void*)buffer, sizeof(buffer));
                if (size) {
                    auto packet = IPPacket::parse(buffer, size);
                    if (packet != nullptr && newIPPktCallback_) {
                        receiveRateCalculator_.update(packet->size()); // calculate rate
                        newIPPktCallback_(std::move(packet));
                    }
                }
            }
            tun_->down();
            tun_->release();
        }
    private:
        const std::uint16_t mtu_;
        std::atomic<bool> running_; 
        std::thread thread_;
        std::unique_ptr<tuntap::tun> tun_;

        const std::string name_;
        const pcpp::IPv4Address addr_;
        const int netmask_;
        NewIPPacketCallback newIPPktCallback_;

        DataRateCalculator sendRateCalculator_;
        DataRateCalculator receiveRateCalculator_;
    };


    using TunInterfacePtr = std::unique_ptr<TunInterface>;

}