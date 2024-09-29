#pragma once

#include <mutex>
#include <thread>
#include <string>
#include <iostream>
#include <functional>

#include <httplib/httplib.h>
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_client.hpp>

#include <common/network/ip_packet.h>


namespace fptn::http
{
    using AsioSslContextPtr = std::shared_ptr<boost::asio::ssl::context>;
    using AsioMessagePtr = websocketpp::config::asio_client::message_type::ptr;
    using AsioClient = websocketpp::client<websocketpp::config::asio_tls_client>;

    class WebSocketClient final
    {
    public:
        using NewIPPacketCallback = std::function<void(fptn::common::network::IPPacketPtr packet)>;
    public:
        WebSocketClient(
            const pcpp::IPv4Address& vpnServerIP,
            int vpnServerPort,
            const pcpp::IPv4Address& tunInterfaceAddress,
            bool useSsl = true,
            const NewIPPacketCallback& newIPPktCallback = nullptr
        );
        bool login(const std::string& username, const std::string& password) noexcept;
        pcpp::IPv4Address getDns() noexcept;
        bool start() noexcept;
        bool stop() noexcept;
        bool send(fptn::common::network::IPPacketPtr packet) noexcept;
        void setNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept;
    private:
        void run() noexcept;
        httplib::Headers getRealBrowserHeaders() noexcept;
    private:
        AsioSslContextPtr onTlsInit() noexcept;
        void onMessage(websocketpp::connection_hdl hdl, AsioMessagePtr msg) noexcept;
    private:
        std::thread th_;
        mutable std::mutex mutex_;

        AsioClient ws_;
        mutable AsioClient::connection_ptr connection_;
        std::atomic<bool> running_;

        const pcpp::IPv4Address vpnServerIP_;
        const int vpnServerPort_;

        std::string token_;
        pcpp::IPv4Address tunInterfaceAddress_;
        NewIPPacketCallback newIPPktCallback_;
    };

    using WebSocketClientPtr = std::unique_ptr<WebSocketClient>;
}
