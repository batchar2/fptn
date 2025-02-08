#include "server.h"
#include "common/utils/utils.h"

#include <functional>

#include <spdlog/spdlog.h>


using namespace fptn::web;


static const std::string HTML_HOME_PAGE = R"HTML(<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FPTN: Current Time</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f0f0f0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                text-align: center;
                padding: 20px;
                background-color: #fff;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                width: 80%;
                max-width: 600px;
                margin: auto;
            }
            #time {
                font-size: 4em;
                margin-bottom: 20px;
            }
            button {
                padding: 10px 20px;
                font-size: 1em;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                transition: background-color 0.3s ease;
            }
            button:hover {
                background-color: #45a049;
            }
            html, body {
                height: 100%;
            }
            body {
                display: flex;
                justify-content: center;
                align-items: center;
                background-color: #ccc;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div id="time">00:00:00</div>
            <button onclick="updateTime()">Update</button>
        </div>
        <script>
            function updateTime() {
                const now = new Date();
                const hours = String(now.getHours()).padStart(2, '0');
                const minutes = String(now.getMinutes()).padStart(2, '0');
                const seconds = String(now.getSeconds()).padStart(2, '0');
                const timeString = `${hours}:${minutes}:${seconds}`;
                document.getElementById('time').textContent = timeString;
            }
            setInterval(updateTime, 1000);
        </script>
    </body>
</html>
)HTML";


Server::Server(
        std::uint16_t port,
        const fptn::nat::TableSPtr& natTable,
        const fptn::user::UserManagerSPtr& userManager,
        const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
        const fptn::statistic::MetricsSPtr& prometheus,
        const std::string& prometheusAccessKey,
        const pcpp::IPv4Address& dnsServerIPv4,
        const pcpp::IPv6Address& dnsServerIPv6,
        std::size_t threadNumber
)
    :
        running_(false),
        port_(port),
        natTable_(natTable),
        userManager_(userManager),
        tokenManager_(tokenManager),
        prometheus_(prometheus),
        prometheusAccessKey_(prometheusAccessKey),
        dnsServerIPv4_(dnsServerIPv4),
        dnsServerIPv6_(dnsServerIPv6),
        threadNumber_(std::max<std::size_t>(1, threadNumber)),
        ioc_(threadNumber_)
{
    using namespace std::placeholders;
    listener_ = std::make_shared<Listener>(
        ioc_,
        port_,
        tokenManager_,
        std::bind(&Server::onWsOpenConnection, this, _1, _2, _3, _4, _5, _6, _7),
        std::bind(&Server::onWsNewIPPacket, this, _1),
        std::bind(&Server::onWsCloseConnection, this, _1)
    );
    listener_->httpRegister(urlHome_, "GET", std::bind(&Server::onApiHandleHome, this, _1, _2));
    listener_->httpRegister(urlDns_, "GET", std::bind(&Server::onApiHandleDns, this, _1, _2));
    listener_->httpRegister(urlLogin_, "POST", std::bind(&Server::onApiHandleLogin, this, _1, _2));
    listener_->httpRegister(urlTestFileBin_, "GET", std::bind(&Server::onApiHandleonTestFile, this, _1, _2));
    if (!prometheusAccessKey.empty()) {
        // Construct the URL for accessing Prometheus statistics by appending the access key
        const std::string metrics = urlMetrics_ + '/' + prometheusAccessKey;
        listener_->httpRegister(
             metrics,
             "GET",
             std::bind(&Server::onApiHandleMetrics, this, _1, _2)
        );
    }
    toClient_ = std::make_unique<fptn::common::data::ChannelAsync>(ioc_);
    fromClient_ = std::make_unique<fptn::common::data::Channel>();
}

Server::~Server()
{
    stop();
}

bool Server::start() noexcept
{
    try {
        // run listener
        boost::asio::co_spawn(
                ioc_,
                [this]() -> boost::asio::awaitable<void> {
                    co_await listener_->run();
                },
                boost::asio::detached
        );
        // run senders
        for (std::size_t i = 0; i < threadNumber_; i++) {
            boost::asio::co_spawn(
                    ioc_,
                    [this]() -> boost::asio::awaitable<void> {
                        co_await runSender();
                    },
                    boost::asio::detached
            );
        }
        // run threads
        iocThreads_.reserve(threadNumber_);
        for (std::size_t i = 0; i < threadNumber_; i++) {
            iocThreads_.emplace_back(
                    [this]() {
                        ioc_.run();
                    }
            );
        }
    } catch (boost::system::system_error& err) {
        spdlog::error("Server::start error: {}", err.what());
        return false;
    }
    running_ = true;
    return true;
}

boost::asio::awaitable<void> Server::runSender()
{
    const std::chrono::milliseconds timeout{5};
    while (running_) {
        auto optpacket = co_await toClient_->waitForPacketAsync(timeout);
        if (optpacket) {
            // find client
            SessionSPtr session = nullptr;
            {
                const std::unique_lock<std::mutex> lock(mutex_);

                auto it = sessions_.find(optpacket->get()->clientId());
                if (it != sessions_.end()) {
                    session = it->second;
                }
            }
            if (session != nullptr) {
                co_await session->send(std::move(*optpacket));
            }
        }
    }
    co_return;
}

bool Server::stop() noexcept
{
    running_ = false;

    for (auto& session : sessions_) {
        session.second->close();
    }

    {
        const std::unique_lock<std::mutex> lock(mutex_);
        sessions_.clear();
    }

    ioc_.stop();
    for (auto& th: iocThreads_) {
        if (th.joinable()) {
            th.join();
        }
    }
    return true;
}

void Server::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    toClient_->push(std::move(packet));
}

fptn::common::network::IPPacketPtr Server::waitForPacket(const std::chrono::milliseconds& duration) noexcept
{
    return fromClient_->waitForPacket(duration);
}

int Server::onApiHandleHome(const http::request& req, http::response& resp) noexcept
{
    (void)req;

    resp.body() = HTML_HOME_PAGE;
    resp.set(boost::beast::http::field::content_type, "text/html; charset=utf-8");
    return 200;
}

int Server::onApiHandleDns(const http::request& req, http::response& resp) noexcept
{
    (void)req;

    resp.body() = fmt::format(
        R"({{"dns": "{}", "dns_ipv6": "{}" }})",
        dnsServerIPv4_.toString(),
        dnsServerIPv6_.toString()
    );
    resp.set(boost::beast::http::field::content_type, "application/json; charset=utf-8");
    return 200;
}

int Server::onApiHandleLogin(const http::request& req, http::response& resp) noexcept
{
    try {
        auto request = nlohmann::json::parse(req.body());
        const auto username = request.at("username").get<std::string>();
        const auto password = request.at("password").get<std::string>();
        int bandwidthBit = 0;
        if (userManager_->login(username, password, bandwidthBit)) {
            spdlog::info("Successful login for user {}", username);
            const auto tokens = tokenManager_->generate(username, bandwidthBit);
            resp.body() = fmt::format(
                R"({{ "access_token": "{}", "refresh_token": "{}", "bandwidth_bit": {} }})",
                tokens.first,
                tokens.second,
                std::to_string(bandwidthBit)
            );
            return 200;
        }
        spdlog::warn("Wrong password for user: \"{}\" ", username);
        resp.body() = R"({"status": "error", "message": "Invalid login or password."})";
    } catch (const nlohmann::json::exception& e) {
        spdlog::error("HTTP JSON AUTH ERROR: {}", e.what());
        resp.body() = R"({"status": "error", "message": "Invalid JSON format."})";
        return 400;
    } catch (const std::exception& e) {
        spdlog::error("HTTP AUTH ERROR: {}", e.what());
        resp.body() = R"({"status": "error", "message": "An unexpected error occurred."})";
        return 500;
    } catch(...) {
        spdlog::error("UNDEFINED SERVER ERROR");
        resp.body() =R"({"status": "error", "message": "Undefined server error"})";
        return 501;
    }
    return 401;
}

int Server::onApiHandleMetrics(const http::request& req, http::response& resp) noexcept
{
    (void)req;

    resp.set(boost::beast::http::field::content_type, "text/html; charset=utf-8");
    resp.body() = prometheus_->collect();
    return 200;
}

int Server::onApiHandleonTestFile(const http::request& req, http::response& resp) noexcept
{
    (void)req;

    static const std::string data = fptn::common::utils::generateRandomString(100*1024);  // 100KB

    resp.set(boost::beast::http::field::content_type, "application/octet-stream");
    resp.body() = data;
    return 200;
}

bool Server::onWsOpenConnection(
        fptn::ClientID clientId,
        const pcpp::IPv4Address& clientIP,
        const pcpp::IPv4Address& clientVpnIPv4,
        const pcpp::IPv6Address& clientVpnIPv6,
        SessionSPtr session,
        const std::string& url,
        const std::string& accessToken
) noexcept
{
    if (url != urlWebSocket_) {
        spdlog::error("Wrong URL \"{}\"", url);
        return false;
    }

    if (clientVpnIPv4 != pcpp::IPv4Address("") && clientVpnIPv6 != pcpp::IPv6Address("")) {
        std::string username;
        std::size_t bandwidthBitesSeconds = 0;
        if(tokenManager_->validate(accessToken, username, bandwidthBitesSeconds)) {
            const std::unique_lock<std::mutex> lock(mutex_);

            if (sessions_.find(clientId) == sessions_.end()) {
                const auto shaperToClient = std::make_shared<fptn::traffic_shaper::LeakyBucket>(
                    bandwidthBitesSeconds
                );
                const auto shaperFromClient = std::make_shared<fptn::traffic_shaper::LeakyBucket>(
                    bandwidthBitesSeconds
                );
                const auto natSession = natTable_->createClientSession(
                    clientId,
                    username,
                    clientVpnIPv4,
                    clientVpnIPv6,
                    shaperToClient,
                    shaperFromClient
                );
                spdlog::info(
                    "NEW SESSION! Username={} ClientId={} Bandwidth={} ClientIP={} VirtualIPv4={} VirtualIPv6={}",
                    username,
                    clientId,
                    bandwidthBitesSeconds,
                    clientIP.toString(),
                    natSession->fakeClientIPv4().toString(),
                    natSession->fakeClientIPv6().toString()
                );
                sessions_.insert({clientId, std::move(session)});
                return true;
            } else {
                spdlog::warn("Client with same ID already exists!");
            }
        } else {
            spdlog::warn("WRONG TOKEN: {}", username);
        }
    } else {
        spdlog::warn("Wrong ClientIP or ClientIPv6");
    }
    return false;
}

void Server::onWsNewIPPacket(fptn::common::network::IPPacketPtr packet) noexcept
{
    fromClient_->push(std::move(packet));
}

void Server::onWsCloseConnection(fptn::ClientID clientId) noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    auto it = sessions_.find(clientId);
    if (it != sessions_.end()) {
        spdlog::info("DEL SESSION! clientId={}", clientId);
        sessions_.erase(it);
        natTable_->delClientSession(clientId);
    }
}
