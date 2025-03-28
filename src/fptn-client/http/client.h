#pragma once

#include <mutex>
#include <thread>
#include <string>
#include <iostream>
#include <functional>

#include <common/https/client.h>
#include <common/network/ip_packet.h>

#include "websocket/websocket.h"


namespace fptn::http
{

    class Client final
    {
    public:
        using NewIPPacketCallback = std::function<void(fptn::common::network::IPPacketPtr packet)>;
    public:
        Client(
            const pcpp::IPv4Address& serverIP,
            int serverPort,
            const pcpp::IPv4Address& tunInterfaceAddressIPv4,
            const pcpp::IPv6Address& tunInterfaceAddressIPv6,
            const std::string& sni,
            const NewIPPacketCallback& newIPPktCallback = nullptr
        );
        bool login(const std::string& username, const std::string& password) noexcept;
        std::pair<pcpp::IPv4Address, pcpp::IPv6Address> getDns() noexcept;
        bool start() noexcept;
        bool stop() noexcept;
        bool send(fptn::common::network::IPPacketPtr packet) noexcept;
        void setNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept;
    protected:
        void run() noexcept;
    private:
        mutable std::thread th_;
        mutable std::mutex mutex_;
        mutable std::atomic<bool> running_;

        const pcpp::IPv4Address serverIP_;
        const int serverPort_;

        const pcpp::IPv4Address tunInterfaceAddressIPv4_;
        const pcpp::IPv6Address tunInterfaceAddressIPv6_;
        const std::string sni_;

        NewIPPacketCallback newIPPktCallback_;

        std::string token_;
        WebsocketSPtr ws_;
    };

    using ClientPtr = std::unique_ptr<Client>;
}
