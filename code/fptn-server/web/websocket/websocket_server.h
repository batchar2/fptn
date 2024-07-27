#pragma once

#include <mutex>
#include <string>
#include <functional>
#include <unordered_map>

#include <glog/logging.h>
#include <hv/WebSocketServer.h>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>

#include <common/network/ip_packet.h>
#include <common/jwt_token/token_manager.h>


namespace fptn::web
{

    class WebsocketServer
    {
    public:
        using NewConnectionCallback = std::function<void(std::uint32_t clientId, const pcpp::IPv4Address& clientVpnIP, const pcpp::IPv4Address& clientIP, const std::string& username, int bandwidthBitesSeconds)>;
        using CloseConnectionCallback = std::function<void(std::uint32_t client_id)>;
        using NewIPPacketCallback = std::function<void(fptn::common::network::IPPacketPtr packet)>;
    public:
        WebsocketServer(
            const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
            const NewConnectionCallback &newConnection,
            const CloseConnectionCallback &closeConnection,
            const NewIPPacketCallback &newPacket
        );
        inline hv::WebSocketService* getService() noexcept
        {
            return &ws_;
        }
        void send(fptn::common::network::IPPacketPtr packet);
    private:
        void onOpenHandle(const WebSocketChannelPtr& channel, const HttpRequestPtr& req) noexcept;
        void onMessageHandle(const WebSocketChannelPtr& channel, const std::string& msg) noexcept;
        void onCloseHandle(const WebSocketChannelPtr& channel) noexcept;
    private:
        mutable std::mutex mutex_;
        hv::WebSocketService ws_;

        const std::string websocket_uri_ = "/fptn";

        fptn::common::jwt_token::TokenManagerSPtr tokenManager_;
        NewConnectionCallback newConnectionCallback_;
        CloseConnectionCallback closeConnectionCallback_;
        NewIPPacketCallback newPacketCallback_;

        std::unordered_map<std::uint32_t, WebSocketChannelPtr> channels_;
    };
}
