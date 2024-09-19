#include "websocket_client.h"

#include <fmt/format.h>
#include <hv/requests.h>
#include <glog/logging.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

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

    hlog_disable();
    ws_.setReconnect(&reconn);
    ws_.onopen = std::bind(&WebSocketClient::onOpenHandle, this);
    ws_.onmessage = std::bind(&WebSocketClient::onMessageHandle, this, std::placeholders::_1);
    ws_.onclose = std::bind(&WebSocketClient::onCloseHandle, this);
}

bool WebSocketClient::login(const std::string& username, const std::string& password) noexcept
{
    const std::string url = fmt::format("https://{}:{}/api/v1/login", vpnServerIP_, vpnServerPort_);
    const std::string request = fmt::format(R"({{ "username": "{}", "password": "{}" }})", username, password);

    auto resp = requests::post(url.c_str(), request, getRealBrowserHeaders());
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

std::string WebSocketClient::getDns() noexcept
{
    const std::string url = fmt::format("https://{}:{}/api/v1/dns", vpnServerIP_, vpnServerPort_);
    auto resp = requests::get(url.c_str(), getRealBrowserHeaders());
    if (resp != nullptr) {
        try {
            auto response = nlohmann::json::parse(resp->body);
            if (response.contains("dns")) {
                const std::string dnsServer = response["dns"];
                return dnsServer;
            } else {
                LOG(ERROR) << "Error: dns not found in the response. Check your conection";
            }
        } catch (const nlohmann::json::parse_error& e) {
            LOG(ERROR) << "Error parsing JSON response: " << e.what() << std::endl << resp->body;
            LOG(ERROR) << "URL: " << url;
        }
    } else {
        LOG(ERROR) << "Error: Request failed or response is null.";
    }
    return {};
}

bool WebSocketClient::start() noexcept
{
    const std::string url = fmt::format("wss://{}:{}/fptn", vpnServerIP_, vpnServerPort_);

    http_headers headers = getRealBrowserHeaders();
    headers["Authorization"] = token_;
    headers["ClientIP"] = tunInterfaceAddress_;

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

http_headers WebSocketClient::getRealBrowserHeaders() noexcept
{
#ifdef __linux__
    // firefox ubuntu arm
    return {
        {"Host", (vpnServerPort_ == 443 ? vpnServerIP_ : fmt::format("{}:{}", vpnServerIP_, vpnServerPort_))},
        {"User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"},
        {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"},
        {"Accept-Language", "en-US,en;q=0.5"},
        {"Accept-Encoding", "gzip, deflate, br, zstd"},
        {"Referer", "https://www.google.com/"},
        {"upgrade-insecure-requests", "1"},
        {"sec-fetch-dest", "document"},
        {"sec-fetch-mode", "navigate"},
        {"sec-fetch-site", "cross-site"},
        {"sec-fetch-user", "?1"},
        {"priority", "u=0, i"},
        {"te", "trailers"}
    };
#elif __APPLE__
    // apple silicon chrome
    return {
        {"Host", (vpnServerPort_ == 443 ? vpnServerIP_ : fmt::format("{}:{}", vpnServerIP_, vpnServerPort_))},
        {"sec-ch-ua", R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
        {"sec-ch-ua-platform", "\"macOS\""},
        {"sec-ch-ua-mobile", "?0"},
        {"upgrade-insecure-requests", "1"},
        {"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
        {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
        {"sec-fetch-site", "none"},
        {"sec-fetch-mode", "no-cors"},
        {"sec-fetch-dest", "empty"},
        {"Referer", "https://www.google.com/"},
        {"Accept-Encoding", "gzip, deflate, br"},
        {"Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
        {"priority", "u=4, i"}
    };
#elif _WIN32
    // chrome windows amd64
    return {
        {"Host", (vpnServerPort_ == 443 ? vpnServerIP_ : fmt::format("{}:{}", vpnServerIP_, vpnServerPort_))},
        {"sec-ch-ua", R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
        {"sec-ch-ua-mobile", "?0"},
        {"sec-ch-ua-platform", "\"Windows\""},
        {"upgrade-insecure-requests", "1"},
        {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
        {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
        {"sec-fetch-site", "cross-site"},
        {"sec-fetch-mode", "navigate"},
        {"sec-fetch-user", "?1"},
        {"sec-fetch-dest", "document"},
        {"Referer", "https://www.google.com/"},
        {"Accept-Encoding", "gzip, deflate, br, zstd"},
        {"Accept-Language", "en-US,en;q=0.9,ru;q=0.8"},
        {"priority", "u=0, i"}
    };
#else
    #error "Unsupported system!"
#endif
}

void WebSocketClient::onOpenHandle() noexcept
{
    LOG(INFO) << "WebSocket connection opened";
}

void WebSocketClient::onMessageHandle(const std::string& msg) noexcept
{
    try {
        std::string rawIpPacket = fptn::common::protobuf::protocol::getPayload(msg);
        auto packet = fptn::common::network::IPPacket::parse(std::move(rawIpPacket));
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
