#pragma once

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <common/data/channel.h>
#include <common/network/ip_packet.h>

#include "nat/table.h"
#include "user/user_manager.h"

#include "listener/listener.h"
#include "common/jwt_token/token_manager.h"


namespace fptn::web
{
    class Server final
    {
    public:
        Server(
            std::uint16_t port,
            const fptn::nat::TableSPtr& natTable,
            const fptn::user::UserManagerSPtr& userManager,
            const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
            const fptn::statistic::MetricsSPtr& prometheus,
            const std::string& prometheusAccessKey,
            const pcpp::IPv4Address& dnsServerIPv4,
            const pcpp::IPv6Address& dnsServerIPv6,
            std::size_t threadNumber = 1
        );
        ~Server();
        bool start() noexcept;
        bool stop() noexcept;
    public:
        void send(fptn::common::network::IPPacketPtr packet) noexcept;
        fptn::common::network::IPPacketPtr waitForPacket(const std::chrono::milliseconds& duration) noexcept;
    private:
//        void newVpnConnection(
//            std::uint32_t clientId,
//            const pcpp::IPv4Address& clientVpnIPv4,
//            const pcpp::IPv6Address& clientVpnIPv6,
//            const pcpp::IPv4Address &clientIP,
//            const std::string& username,
//            std::size_t bandwidthBitesSeconds
//        ) noexcept;
//        void closeVpnConnection(std::uint32_t clientId) noexcept;
//        void newIPPacketFromVPN(fptn::common::network::IPPacketPtr packet) noexcept;
    protected:
//        void runServerThread() noexcept;
        void runSenderThread() noexcept;
    protected:
        // http
        int onApiHandleHome(const http::request& req, http::response& resp) noexcept;
        int onApiHandleDns(const http::request& req, http::response& resp) noexcept;
        int onApiHandleLogin(const http::request& req, http::response& resp) noexcept;
        int onApiHandleMetrics(const http::request& req, http::response& resp) noexcept;
        int onApiHandleonTestFile(const http::request& req, http::response& resp) noexcept;
        // websocket
        bool onWsOpenConnection(
            fptn::ClientID clientId,
            const pcpp::IPv4Address& clientIP,
            const pcpp::IPv4Address& clientVpnIPv4,
            const pcpp::IPv6Address& clientVpnIPv6,
            SessionSPtr session,
            const std::string& url,
            const std::string& accessToken
        ) noexcept;
        void onWsNewIPPacket(fptn::common::network::IPPacketPtr packet) noexcept;
        void onWsCloseConnection(fptn::ClientID clientId) noexcept;
    private:
        const std::string urlHome_="/";
        const std::string urlDns_="/api/v1/dns";
        const std::string urlLogin_="/api/v1/login";
        const std::string urlMetrics_="/api/v1/metrics";
        const std::string urlTestFileBin_="/api/v1/test/file.bin";

        const std::string urlWebSocket_="/fptn";

        std::mutex mutex_;
        std::atomic<bool> running_;
        std::uint16_t port_;

        const fptn::nat::TableSPtr& natTable_;
        const fptn::user::UserManagerSPtr& userManager_;
        fptn::common::jwt_token::TokenManagerSPtr tokenManager_;
        const fptn::statistic::MetricsSPtr& prometheus_;
        const std::string prometheusAccessKey_;
        const pcpp::IPv4Address dnsServerIPv4_;
        const pcpp::IPv6Address dnsServerIPv6_;
        const std::size_t threadNumber_;

        boost::asio::io_context ioCtx_;
        fptn::common::data::Channel toClient_;
        fptn::common::data::Channel fromClient_;

        ListenerSPtr listener_;

        std::vector<std::thread> iocThreads_;

        std::thread senderThread_;

        std::unordered_map<fptn::ClientID, SessionSPtr> sessions_;
    };

    using ServerPtr = std::unique_ptr<Server>;
    
}
