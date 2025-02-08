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
            const std::string &name,
            const pcpp::IPv4Address& ipv4Address,
            const int ipv4Netmask,
            const pcpp::IPv6Address& ipv6Address,
            const int ipv6Netmask,
            fptn::system::IPTablesPtr iptables
        );
        ~VirtualInterface();
        bool check() noexcept;
        bool start() noexcept;
        bool stop() noexcept;
        void send(fptn::common::network::IPPacketPtr packet) noexcept;
        fptn::common::network::IPPacketPtr waitForPacket(const std::chrono::milliseconds& duration) noexcept;
    protected:
        void run() noexcept;
        void newIPPacketFromNetwork(fptn::common::network::IPPacketPtr packet) noexcept;
    private:
        std::atomic<bool> running_;
        fptn::system::IPTablesPtr iptables_;
        fptn::common::data::Channel toNetwork_;
        fptn::common::data::Channel fromNetwork_;
        fptn::common::network::TunInterfacePtr virtualNetworkInterface_;

        std::thread thread_;
    };

    using VirtualInterfacePtr = std::unique_ptr<VirtualInterface>;
}
