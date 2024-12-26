#pragma once

#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <string>
#include <functional>
#include <unordered_map>

#include <hv/WebSocketServer.h>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>

#include <common/network/ip_packet.h>
#include <common/jwt_token/token_manager.h>


namespace fptn::web
{
    #define WEBSOCKET_IDLE_TIMEOUT_SECONDS (120)

    class WebsocketServer final
    {
    public:
        using NewConnectionCallback = std::function<void(
            std::uint32_t clientId,
            const pcpp::IPv4Address& clientVpnIPv4,
            const pcpp::IPv6Address& clientVpnIPv6,
            const pcpp::IPv4Address& clientIP,
            const std::string& username,
            std::size_t bandwidthBitesSeconds
        )>;
        using CloseConnectionCallback = std::function<void(std::uint32_t client_id)>;
        using NewIPPacketCallback = std::function<void(fptn::common::network::IPPacketPtr packet)>;
    public:
        WebsocketServer(
            const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
            const NewConnectionCallback &newConnection,
            const CloseConnectionCallback &closeConnection,
            const NewIPPacketCallback &newPacket
        );
        ~WebsocketServer();
        hv::WebSocketService* getService() noexcept;
        void send(fptn::common::network::IPPacketPtr packet) noexcept;
    private:
        void run() noexcept;
        void onOpenHandle(const WebSocketChannelPtr& channel, const HttpRequestPtr& req) noexcept;
        void onMessageHandle(const WebSocketChannelPtr& channel, const std::string& msg) noexcept;
        void onCloseHandle(const WebSocketChannelPtr& channel) noexcept;
    private:
        const std::string websocket_uri_ = "/fptn";

        std::atomic<bool> running_;

        std::thread thread_;
        mutable std::mutex mutex_;
        hv::WebSocketService ws_;

        fptn::common::jwt_token::TokenManagerSPtr tokenManager_;
        NewConnectionCallback newConnectionCallback_;
        CloseConnectionCallback closeConnectionCallback_;
        NewIPPacketCallback newPacketCallback_;

        std::unordered_map<std::uint32_t, WebSocketChannelPtr> channels_;
        std::unordered_map<std::uint32_t, std::chrono::steady_clock::time_point> channelsLastActive_;
    };
}
