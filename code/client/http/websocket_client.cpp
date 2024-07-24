#include "websocket_client.h"


using namespace fptn::http;


WebSocketClient::WebSocketClient(
    const std::string& url,
    const std::string& token,
    const std::string& interfaceAddress,
    bool useSsl,
    const NewIPPacketCallback& newIPPktCallback 
)
    :
        url_(url),
        token_(token),
        newIPPktCallback_(newIPPktCallback)
{
    reconn_setting_t reconn;
    reconn_setting_init(&reconn);
    reconn.min_delay = 1000;
    reconn.max_delay = 10000;
    reconn.delay_policy = 2;

    ws_.setReconnect(&reconn);

    http_headers headers = {
            {"Authorization", token},
            {"ClientIP", interfaceAddress}
    };
    if (ws_.open(url.c_str(), headers) != 0) {
        std::cerr << "Failed to open WebSocket connection" << std::endl;
//        throw std::runtime_error("Failed to open WebSocket connection");
    }
    ws_.onopen = std::bind(&WebSocketClient::onOpenHandle, this);
    ws_.onmessage = std::bind(&WebSocketClient::onMessageHandle, this, std::placeholders::_1);
    ws_.onclose = std::bind(&WebSocketClient::onCloseHandle, this);
}

bool WebSocketClient::start() noexcept
{
    std::lock_guard<std::mutex> lock(mtx_);
    th_ = std::thread(&WebSocketClient::run, this);
    return th_.joinable();
}

bool WebSocketClient::stop() noexcept
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (th_.joinable()) {
        ws_.stop();
        th_.join();
        return true;
    }
    return false;
}

void WebSocketClient::setNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept
{
    newIPPktCallback_ = callback;
}

bool WebSocketClient::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    std::vector<std::uint8_t> serializedPacket = packet->serialize();
    ws_.send((const char*)serializedPacket.data(), serializedPacket.size());
    return true;
}

void WebSocketClient::run() noexcept
{
    // pass
}

void WebSocketClient::onOpenHandle() noexcept
{
    std::cout << "WebSocket connection opened" << std::endl;
}

void WebSocketClient::onMessageHandle(const std::string& msg) noexcept
{
    auto packet = fptn::common::network::IPPacket::parse((const std::uint8_t*)msg.c_str(), msg.size());
    if (packet != nullptr && newIPPktCallback_) {
        newIPPktCallback_(std::move(packet));
    }
}

void WebSocketClient::onCloseHandle() noexcept
{
    std::cout << "WebSocket connection closed" << std::endl;
}
