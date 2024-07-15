#pragma once

#include <string>
#include <iostream>
#include <functional>

#include <glog/logging.h>
#include <hv/WebSocketServer.h>


namespace fptn::web
{

    class websocket
    {
    public:
        using new_connection_callback = std::function<void(const WebSocketChannelPtr&, const std::string &client_ip, const std::uint32_t client_id)>;
        using close_connection_callback = std::function<void(const WebSocketChannelPtr&, const std::uint32_t client_id)>;
        using recv_packet_callback = std::function<void(const std::string& raw_ip_data, const std::uint32_t client_id)>;
    public:
        websocket(const new_connection_callback &new_connection,
            const close_connection_callback &close_connection,
            const recv_packet_callback &recv_packet = nullptr
        );
        hv::WebSocketService* get_service() noexcept;
        void set_recv_packet_callback(const recv_packet_callback &recv_packet) noexcept;
    private:
        void on_open_handle(const WebSocketChannelPtr& channel, const HttpRequestPtr& req) noexcept;
        void on_message_handle(const WebSocketChannelPtr& channel, const std::string& msg) noexcept;
        void on_close_handle(const WebSocketChannelPtr& channel) noexcept;
    private:
        hv::WebSocketService ws_;

        const std::string websocket_uri_ = "/fptn";

        new_connection_callback new_connection_callback_;
        close_connection_callback close_connection_callback_;
        recv_packet_callback recv_packet_callback_;
    };
}
