#pragma once

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
#include "eth_packet.h"


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


    #define FPTN_MTU    (1500)
    using NewIPPacketCallback = std::function<void(IPPacketPtr packet)>;

    class BaseNetInterface
    {
    public:
        BaseNetInterface() {}
        virtual ~BaseNetInterface() {}
        virtual bool start() noexcept = 0;
        virtual bool stop() noexcept = 0;
        virtual bool send(IPPacketPtr packet) noexcept = 0;
        virtual void setNewIPPacketCallback(const NewIPPacketCallback &callback) noexcept  = 0;
        virtual std::size_t getSendRate() const noexcept = 0;
        virtual std::size_t getReceiveRate() const noexcept = 0;
    };

    template<class T>
    class NetInterface : public BaseNetInterface
    {
    public:
        NetInterface(
                const std::string &name,
                const pcpp::IPv4Address &addr,
                const int netmask,
                const NewIPPacketCallback &callback = nullptr
        )
            :
                mtu_(FPTN_MTU),
                running_(false),
                name_(name),
                addr_(addr),
                netmask_(netmask),
                newIPPktCallback_(callback)
        {
        }

        virtual ~NetInterface()
        {
            stop();
        }

        virtual bool start() noexcept override
        {
            try {
                net_interface_ = std::make_unique<T>();
                net_interface_->name(name_);
                net_interface_->ip(addr_.toString(), netmask_);
                net_interface_->mtu(mtu_);
                net_interface_->nonblocking(true);
                net_interface_->up();
                running_ = true;
                thread_ = std::thread(&NetInterface<T>::run, this);
                return thread_.joinable();
            } catch (const std::exception &ex) {
                LOG(ERROR) << "Error start: " << ex.what() << std::endl;
            }
            return false;
        }

        virtual bool stop() noexcept override
        {
            if (thread_.joinable() && running_ && net_interface_) {
                running_ = false;
                thread_.join();
                net_interface_.reset();
                return true;
            }
            return false;
        }

        virtual bool send(IPPacketPtr packet) noexcept override
        {
            if (running_) {
                sendRateCalculator_.update(packet->size()); // calculate rate
                auto serialized = serializeNetPacket(std::move(packet));
                return net_interface_->write(serialized.data(), serialized.size()) == serialized.size();
            }
            return false;
        }

        virtual void setNewIPPacketCallback(const NewIPPacketCallback &callback) noexcept override
        {
            newIPPktCallback_ = callback;
        }

        virtual std::size_t getSendRate() const noexcept override
        {
            return sendRateCalculator_.getRateForSecond();
        }

        virtual std::size_t getReceiveRate() const noexcept override
        {
            return receiveRateCalculator_.getRateForSecond();
        }

        pcpp::MacAddress hwaddr() const noexcept
        {
            return pcpp::MacAddress(net_interface_->hwaddr());
        }
    protected:
        virtual IPPacketPtr toIPPacket(const std::uint8_t* buffer, std::size_t size) = 0;
        virtual std::vector<std::uint8_t> serializeNetPacket(IPPacketPtr packet) = 0;
    private:
        void run() noexcept
        {
            // FIX IT!!!
            std::uint8_t buffer[FPTN_MTU+1] = {0};
            while(running_) {
                std::memset(buffer, 0, mtu_ + 1);
                int size = net_interface_->read((void*)buffer, sizeof(buffer));
                if (size > 0 && running_) {
                    auto packet= toIPPacket(buffer, size);
                    if (packet != nullptr && newIPPktCallback_) {
                        receiveRateCalculator_.update(packet->size()); // calculate rate
                        newIPPktCallback_(std::move(packet));
                    }
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        }
    private:
        const std::uint16_t mtu_;
        std::atomic<bool> running_;
        std::thread thread_;
        std::unique_ptr<T> net_interface_;

        const std::string name_;
        const pcpp::IPv4Address addr_;
        const int netmask_;
        NewIPPacketCallback newIPPktCallback_;

        DataRateCalculator sendRateCalculator_;
        DataRateCalculator receiveRateCalculator_;
    };


    class TunInterface : public NetInterface<tuntap::tun>
    {
    public:
        TunInterface(
            const std::string& name,
            const pcpp::IPv4Address& addr,
            const int netmask,
            const NewIPPacketCallback& callback = nullptr
        )
            : NetInterface<tuntap::tun>(name, addr, netmask, callback)
        {
        }
        virtual ~TunInterface() {}
    protected:
        virtual IPPacketPtr toIPPacket(const std::uint8_t* buffer, std::size_t size) override
        {
            return IPPacket::parse(buffer, size);
        }
        virtual std::vector<std::uint8_t> serializeNetPacket(IPPacketPtr packet) override
        {
            std::vector<std::uint8_t> data = packet->serialize();
            return data;
        }
    };


    class TapInterface : public NetInterface<tuntap::tap>
    {
    public:
        TapInterface(
            const std::string& name,
            const pcpp::IPv4Address& addr,
            const int netmask,
            const NewIPPacketCallback& callback = nullptr
        )
            : NetInterface<tuntap::tap>(name, addr, netmask, callback)
        {
        }
        virtual ~TapInterface() {}
    protected:
        virtual IPPacketPtr toIPPacket(const std::uint8_t* buffer, std::size_t size) override
        {
            return EthPacket::extractIPPacket(buffer, size);
        }
        virtual std::vector<std::uint8_t> serializeNetPacket(IPPacketPtr packet) override
        {
            std::vector<std::uint8_t> data = EthPacket::serializeData(std::move(packet), hwaddr());
            return data;
        }
    };

    using BaseNetInterfacePtr = std::unique_ptr<BaseNetInterface>;
    using TapInterfacePtr = std::unique_ptr<TapInterface>;
    using TunInterfacePtr = std::unique_ptr<TunInterface>;
}