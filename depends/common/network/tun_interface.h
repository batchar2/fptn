#pragma once

#include <queue>
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

    using NewIPPacketCallback = std::function<void(IPPacketPtr packet)>;
    
    class TunInterface
    {
    public:
        TunInterface(
            std::string name, 
            std::string addr, 
            const int netmask, 
            const NewIPPacketCallback& callback = nullptr
        )
            : 
                name_(std::move(name)),
                addr_(std::move(addr)),
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
                tun_->ip(addr_, netmask_);
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
            std::vector<std::uint8_t> serialized = packet->serialize();
            return tun_->write(serialized.data(), serialized.size()) == serialized.size();
        }
    private:
        void run() noexcept
        {
            std::uint8_t buffer[65536] = {0};
            while(running_) {
                std::memset(buffer, 0, sizeof(buffer));
                int size = tun_->read((void*)buffer, sizeof(buffer));
                if (size) {
                    auto packet = IPPacket::parse(buffer, size);
                    if (packet != nullptr && newIPPktCallback_) {
                        newIPPktCallback_(std::move(packet));
                    }
                }
            }
            tun_->down();
            tun_->release();
        }
    private:
        std::atomic<bool> running_ = false; 
        std::thread thread_;
        std::unique_ptr<tuntap::tun> tun_;

        const std::string name_;
        const std::string addr_;
        const int netmask_;
        NewIPPacketCallback newIPPktCallback_;
    };


    using TunInterfacePtr = std::unique_ptr<TunInterface>;

}