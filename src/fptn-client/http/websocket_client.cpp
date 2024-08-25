#include "websocket_client.h"

#include <fmt/format.h>
#include <hv/requests.h>
#include <glog/logging.h>

#include <common/protobuf/protocol.h>

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

    auto resp = requests::post(url.c_str(), request);
    if (resp != nullptr) {
        try {
            auto response = nlohmann::json::parse(resp->body);
            if (response.contains("access_token")) {
                token_ = response["access_token"];
                LOG(INFO) << "Login successful.";
                return true;
            } else {
                LOG(ERROR) << "Error: Access token not found in the response. Check your conection";
            }
        } catch (const nlohmann::json::parse_error& e) {
            LOG(ERROR) << "Error parsing JSON response: " << e.what() << std::endl << resp->body;
            LOG(ERROR) << "URL: " << url;
        }
    } else {
        LOG(ERROR) << "Error: Request failed or response is null.";
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
        LOG(ERROR) << "Failed to open WebSocket connection" << std::endl;
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
    try {
        const std::string msg = fptn::common::protobuf::protocol::createPacket(
            std::move(packet)
        );
        ws_.send(msg);
        return true;
    } catch (const std::runtime_error &err) {
        LOG(ERROR) << "send error: " << err.what();
    }
    return false;
}

void WebSocketClient::run() noexcept
{
    // pass
}

void WebSocketClient::onOpenHandle() noexcept
{
    LOG(INFO) << "WebSocket connection opened";
}

void WebSocketClient::onMessageHandle(const std::string& msg) noexcept
{
    try {
        const std::string rawIpPacket = fptn::common::protobuf::protocol::getPayload(msg);
        auto packet = fptn::common::network::IPPacket::parse(rawIpPacket);
        if (packet != nullptr && newIPPktCallback_) {
            newIPPktCallback_(std::move(packet));
        }
    } catch (const fptn::common::protobuf::protocol::ProcessingError &err) {
        LOG(ERROR) << "Processing error: " << err.what();
        const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_DEFAULT);
    } catch (const fptn::common::protobuf::protocol::MessageError &err) {
        LOG(ERROR) << "Message error: " << err.what();
    } catch (const fptn::common::protobuf::protocol::UnsoportedProtocolVersion &err) {
        LOG(ERROR) << "Unsupported protocol version: " << err.what();
        const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_WRONG_VERSION);
    } catch(...) {
        LOG(ERROR) << "Unexpected error: ";
    }
}

void WebSocketClient::onCloseHandle() noexcept
{
    LOG(INFO) << "WebSocket connection closed";
}
