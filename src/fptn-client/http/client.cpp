#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include "system/iptables.h"

#include "client.h"


using namespace fptn::http;


Client::Client(
        const pcpp::IPv4Address& serverIP,
        int serverPort,
        const pcpp::IPv4Address& tunInterfaceAddressIPv4,
        const pcpp::IPv6Address& tunInterfaceAddressIPv6,
        const std::string& sni,
        const NewIPPacketCallback& newIPPktCallback
)
    :
        running_(false),
        serverIP_(serverIP),
        serverPort_(serverPort),
        tunInterfaceAddressIPv4_(tunInterfaceAddressIPv4),
        tunInterfaceAddressIPv6_(tunInterfaceAddressIPv6),
        sni_(sni),
        newIPPktCallback_(newIPPktCallback)
{
}

bool Client::login(const std::string& username, const std::string& password) noexcept
{
    const std::string request = fmt::format(R"({{ "username": "{}", "password": "{}" }})", username, password);

    fptn::common::https::Client cli(serverIP_.toString(), serverPort_, sni_);
    const auto resp = cli.post("/api/v1/login", request, "application/json");
    if (resp.code == 200) {
        try {
            const auto msg = resp.json();
            if (msg.contains("access_token")) {
                token_ = msg["access_token"];
                SPDLOG_INFO("Login successful");
                return true;
            } else {
                SPDLOG_ERROR("Error: Access token not found in the response. Check your conection");
            }
        }  catch (const nlohmann::json::parse_error& e) {
            SPDLOG_ERROR("Error parsing JSON response: {} ", e.what());
        }
    } else {
        SPDLOG_ERROR("Error: Request failed code: {} msg: {}", resp.code, resp.errmsg);
    }
    return false;
}

std::pair<pcpp::IPv4Address, pcpp::IPv6Address> Client::getDns() noexcept
{
    SPDLOG_INFO("DNS. Connect to {}:{}", serverIP_.toString(), serverPort_);

    fptn::common::https::Client cli(serverIP_.toString(), serverPort_, sni_);
    const auto resp = cli.get("/api/v1/dns");
    if (resp.code == 200) {
        try {
            const auto msg = resp.json();
            if (msg.contains("dns")) {
                const std::string dnsServerIPv4 = msg["dns"];
                const std::string dnsServerIPv6 = (
                    msg.contains("dns_ipv6")
                    ? msg["dns_ipv6"]
                    : FPTN_SERVER_DEFAULT_ADDRESS_IP6 // default for old servers
                );
                return {pcpp::IPv4Address(dnsServerIPv4), pcpp::IPv6Address(dnsServerIPv6)};
            } else {
                SPDLOG_ERROR("Error: dns not found in the response. Check your conection");
            }
        } catch (const nlohmann::json::parse_error &e) {
            SPDLOG_ERROR("Error parsing JSON response: {}", e.what());
        }
    } else {
        SPDLOG_ERROR("Error: Request failed code: {} msg: {}", resp.code, resp.errmsg);
    }
    return {pcpp::IPv4Address("0.0.0.0"), pcpp::IPv6Address("")};
}

void Client::setNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept
{
    newIPPktCallback_ = callback;
}

bool Client::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    try {
        if (ws_ && running_) {
            ws_->send(std::move(packet));
            return true;
        }
    } catch (const std::runtime_error &err) {
        SPDLOG_ERROR("Send error: {}", err.what());
    } catch (const std::exception &e) {
        SPDLOG_ERROR("Exception occurred: {}", e.what());
    }
    return false;
}

void Client::run() noexcept
{
    while (running_)
    {
        {
            const std::unique_lock<std::mutex> lock(mutex_);
            ws_ = std::make_shared<Websocket>(
                serverIP_,
                serverPort_,
                tunInterfaceAddressIPv4_,
                tunInterfaceAddressIPv6_,
                newIPPktCallback_,
                sni_,
                token_
            );
        }
        ws_->run();

        if (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            SPDLOG_ERROR("Connection closed");
        }
    }
}

bool Client::start() noexcept
{
    running_ = true;
    th_ = std::thread(&Client::run, this);
    return th_.joinable();
}

bool Client::stop() noexcept
{
    if (running_ && th_.joinable()) {
        running_ = false;
        {
            const std::unique_lock<std::mutex> lock(mutex_);
            ws_->stop();
        }
        th_.join();
        return true;
    }
    return false;
}

bool Client::isStarted() noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    return ws_ && ws_->isStarted();
}
