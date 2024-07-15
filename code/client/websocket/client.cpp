#include "client.h"

using namespace fptn::websocket;

client::client(
    const std::string& url,
    const std::string& token,
    const std::string& interface_address,
    bool use_ssl,
    const recv_packet_callback& recv_packet
)
    :
        url_(url),
        token_(token),
        recv_packet_callback_(recv_packet)
{
    reconn_setting_t reconn;
    reconn_setting_init(&reconn);
    reconn.min_delay = 1000;
    reconn.max_delay = 10000;
    reconn.delay_policy = 2;

    ws_.setReconnect(&reconn);

    http_headers headers = {
            {"Authorization", token},
            {"ClientIP", interface_address}
    };
    if (ws_.open(url.c_str(), headers) != 0) {
        std::cerr << "Failed to open WebSocket connection" << std::endl;
//        throw std::runtime_error("Failed to open WebSocket connection");
    }
    ws_.onopen = std::bind(&client::on_open_handle, this);
    ws_.onmessage = std::bind(&client::on_message_handle, this, std::placeholders::_1);
    ws_.onclose = std::bind(&client::on_close_handle, this);
}

bool client::start(const recv_packet_callback& recv_packet) noexcept
{
    recv_packet_callback_ = recv_packet;
    std::lock_guard<std::mutex> lock(mtx_);
    th_ = std::thread(&client::run, this);
    return th_.joinable();
}

bool client::stop() noexcept
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (th_.joinable()) {
        ws_.stop();
        th_.join();
        return true;
    }
    return false;
}

bool client::send(const std::string& msg) noexcept
{
    return ws_.send(msg);
}

void client::run() noexcept
{
    // pass
}

void client::on_open_handle() noexcept
{
    std::cout << "WebSocket connection opened" << std::endl;
}

void client::on_message_handle(const std::string& msg) noexcept
{
    if (recv_packet_callback_) {
        recv_packet_callback_(msg);
    }
}

void client::on_close_handle() noexcept
{
    std::cout << "WebSocket connection closed" << std::endl;
}
