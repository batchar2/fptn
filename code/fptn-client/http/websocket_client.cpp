#include "websocket_client.h"

#include <fmt/format.h>
#include <hv/requests.h>


using namespace fptn::http;


WebSocketClient::WebSocketClient(
    const std::string& vpnServerIP, 
    int vpnServerPort,
    const std::string& tunInterfaceAddress,
    bool useSsl,
    const NewIPPacketCallback& newIPPktCallback 
)
    :
        vpnServerIP_(vpnServerIP), 
        vpnServerPort_(vpnServerPort),
        token_(""),
        tunInterfaceAddress_(tunInterfaceAddress),
        newIPPktCallback_(newIPPktCallback)
{
    reconn_setting_t reconn;
    reconn_setting_init(&reconn);
    reconn.min_delay = 1000;
    reconn.max_delay = 10000;
    reconn.delay_policy = 2;

    ws_.setReconnect(&reconn);
    ws_.onopen = std::bind(&WebSocketClient::onOpenHandle, this);
    ws_.onmessage = std::bind(&WebSocketClient::onMessageHandle, this, std::placeholders::_1);
    ws_.onclose = std::bind(&WebSocketClient::onCloseHandle, this);
}

bool WebSocketClient::login(const std::string& username, const std::string& password) noexcept
{
    const std::string url = fmt::format("https://{}:{}/api/v1/login", vpnServerIP_, vpnServerPort_);
    const std::string request = fmt::format(R"({{ "username": "{}", "password": "{}" }})", username, password);

    std::cerr << "URL>" << url << std::endl;
    std::cerr << request << std::endl;

    auto resp = requests::post(url.c_str(), request);
    if (resp != nullptr) {
        try {
            auto response = nlohmann::json::parse(resp->body);
            if (response.contains("access_token")) {
                token_ = response["access_token"];
                std::cerr << "Login successful." << std::endl;
                return true;
            } else {
                std::cerr << "Error: Access token not found in the response." << std::endl;
            }
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << "Error parsing JSON response: " << e.what() << std::endl;
        }
    } else {
        std::cerr << "Error: Request failed or response is null." << std::endl;
    }
    return false;
}

bool WebSocketClient::start() noexcept
{
    const std::string url = fmt::format("wss://{}:{}/fptn", vpnServerIP_, vpnServerPort_);

    http_headers headers = {
        {"Authorization", token_},
        {"ClientIP", tunInterfaceAddress_}
    };
    if (ws_.open(url.c_str(), headers) != 0) {
        std::cerr << "Failed to open WebSocket connection" << std::endl;
    }

    th_ = std::thread(&WebSocketClient::run, this);
    return th_.joinable();
}

bool WebSocketClient::stop() noexcept
{
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
