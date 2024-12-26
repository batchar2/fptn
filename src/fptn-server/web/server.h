#pragma once

#include "nat/table.h"
#include "http/http_server.h"
#include "user/user_manager.h"
#include "websocket/websocket_server.h"

#include <common/data/channel.h>
#include <common/network/ip_packet.h>


namespace fptn::web
{
    class Server final
    {
    public:
        Server(
            const fptn::nat::TableSPtr& natTable,
            std::uint16_t port,
            bool use_https,
            const fptn::user::UserManagerSPtr& userManager,
            const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
            const fptn::statistic::MetricsSPtr& prometheus,
            const std::string& prometheusAccessKey,
            const pcpp::IPv4Address& dnsServerIPv4,
            const pcpp::IPv6Address& dnsServerIPv6,
            int thread_number = 4
        );
        ~Server();
        bool check() noexcept;
        bool start() noexcept;
        bool stop() noexcept;
    public:
        void send(fptn::common::network::IPPacketPtr packet) noexcept;
        fptn::common::network::IPPacketPtr waitForPacket(const std::chrono::milliseconds& duration) noexcept;
    private:
        void newVpnConnection(
            std::uint32_t clientId,
            const pcpp::IPv4Address& clientVpnIPv4,
            const pcpp::IPv6Address& clientVpnIPv6,
            const pcpp::IPv4Address &clientIP,
            const std::string& username,
            const std::size_t bandwidthBitesSeconds
        ) noexcept;
        void closeVpnConnection(std::uint32_t clientId) noexcept;
        void newIPPacketFromVPN(fptn::common::network::IPPacketPtr packet) noexcept;
    private:
        void runServerThread() noexcept;
        void runSenderThread() noexcept;
    private:
        std::atomic<bool> running_; 
        fptn::nat::TableSPtr natTable_;
        fptn::common::data::Channel toClient_;
        fptn::common::data::Channel fromClient_;

        std::thread thread_;
        HttpServer http_;
        WebsocketServer ws_;
        hv::WebSocketServer mainServer_;

        std::thread serverThread_;
        std::thread senderThread_;
    };

    using ServerPtr = std::unique_ptr<Server>;
    
}
