#pragma once

#include <queue>
#include <memory>
#include <string>
#include <thread>
#include <functional>

#include <tuntap++.hh>
#include <glog/logging.h>


namespace fptn::network
{

    using packet_callback = std::function<void(const std::string& packet)>;
    
    class tun_interface
    {
    public:
        tun_interface(std::string name, std::string addr, const int netmask)
            : 
                name_(std::move(name)),
                addr_(std::move(addr)),
                netmask_(netmask),
                pkt_callback_(nullptr)
        {
        }

        bool start(packet_callback callback = nullptr) noexcept
        {            
            try {
                pkt_callback_ = callback;
                tun_ = std::make_unique<tuntap::tun>();
                tun_->name(name_);
                tun_->ip(addr_, netmask_);
                tun_->up();
                running_ = true;
                th_ = std::thread(&tun_interface::run, this);
                return th_.joinable();
            } catch (const std::exception& ex) {
                LOG(ERROR) << "Error start: " << ex.what() << std::endl;
            }
            return false;
        }
        bool stop() noexcept
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (th_.joinable()) {
                running_ = false;
                th_.join();
                return true;
            }
            return false;
        }
        bool send(const std::string& packet) noexcept
        {
            return tun_->write((void*)packet.c_str(), packet.size()) == packet.size();
        }
        bool send(void* data, std::size_t size) noexcept
        {
            return tun_->write(data, size) == size;
        }
    private:
        void run() noexcept
        {
            char buffer[65536] = {0};
            while(running_) {
                std::memset(buffer, 0, sizeof(buffer));
                int size = tun_->read((void*)buffer, sizeof(buffer));
                if (size) {
                    const std::string packet(buffer, size);
                    if (pkt_callback_) {
                        pkt_callback_(packet);
                    }
                }
            }
            tun_->down();
            tun_->release();
        }
    private:
        std::atomic<bool> running_ = false; 
        std::thread th_;
        std::mutex mtx_;
        std::unique_ptr<tuntap::tun> tun_;

        const std::string name_;
        const std::string addr_;
        const int netmask_;
        packet_callback pkt_callback_;
    };

}