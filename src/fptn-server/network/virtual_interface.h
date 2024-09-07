#pragma once

#include <chrono>
#include <thread>
#include <string>

#include <common/data/channel.h>
#include <common/network/ip_packet.h>
#include <common/network/net_interface.h>

#include "system/iptables.h"


namespace fptn::network
{
    class VirtualInterface final
    {
    public:
        VirtualInterface(
            const std::string& name,
            const pcpp::IPv4Address& ipAddress,
            std::uint16_t netmask,
            fptn::system::IPTablesPtr iptables
        );
        ~VirtualInterface();
        bool check() noexcept;
        bool start() noexcept;
        bool stop() noexcept;
    public:
        inline void send(fptn::common::network::IPPacketPtr packet) noexcept
        {
            toNetwork_.push(std::move(packet));
        }
        inline fptn::common::network::IPPacketPtr waitForPacket(const std::chrono::milliseconds& duration)  noexcept
        {
            return fromNetwork_.waitForPacket(duration);
        }
    private:
        void run() noexcept;
        void newIPPacketFromNetwork(fptn::common::network::IPPacketPtr packet) noexcept;
    private:
        fptn::system::IPTablesPtr iptables_;
        std::atomic<bool> running_ = false; 
        fptn::common::data::Channel toNetwork_;
        fptn::common::data::Channel fromNetwork_;
        fptn::common::network::TunInterfacePtr virtualNetworkInterface_;

        std::thread thread_;
    };

    using VirtualInterfacePtr = std::unique_ptr<VirtualInterface>;
}
