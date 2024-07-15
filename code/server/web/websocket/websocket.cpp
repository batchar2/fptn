#include "websocket.h"

using namespace fptn::web;


websocket::websocket(
        const new_connection_callback& new_connection,
        const close_connection_callback& close_connection,
        const recv_packet_callback& recv_packet
)
    :
        new_connection_callback_(new_connection),
        close_connection_callback_(close_connection),
        recv_packet_callback_(recv_packet)
{
        ws_.onopen = std::bind(&websocket::on_open_handle, this, std::placeholders::_1, std::placeholders::_2);
        ws_.onmessage = std::bind(&websocket::on_message_handle, this, std::placeholders::_1, std::placeholders::_2);
        ws_.onclose = std::bind(&websocket::on_close_handle, this, std::placeholders::_1);
}

hv::WebSocketService* websocket::get_service() noexcept
{
    return &ws_;
}

void websocket::set_recv_packet_callback(const recv_packet_callback& recv_packet) noexcept
{
    recv_packet_callback_ = recv_packet;
}

void websocket::on_open_handle(const WebSocketChannelPtr& channel, const HttpRequestPtr& req) noexcept
{
    if (websocket_uri_ == req->Path()) {
        if (req->headers.find("Authorization") != req->headers.end() && req->headers.find("ClientIP") != req->headers.end()) {
            const std::string token = req->headers["Authorization"];
            const std::string client_ip = req->headers["ClientIP"];

            if (new_connection_callback_)  {
                new_connection_callback_(channel, client_ip, channel->id());
            }
        } else {
            std::cerr << "CHECK: Authorization or ClientIP" << std::endl;
        }
    } else {
        std::cerr << "WRONG PATH: " << req->Path() << ", but the real path is: " << websocket_uri_ << std::endl;
        channel->close();
    }
}

void websocket::on_message_handle(const WebSocketChannelPtr& channel, const std::string& msg) noexcept
{
    if (recv_packet_callback_) {
        recv_packet_callback_(msg, channel->id());
    }
}

void websocket::on_close_handle(const WebSocketChannelPtr& channel) noexcept
{
    if (close_connection_callback_) {
        close_connection_callback_(channel, channel->id());
    }
}
