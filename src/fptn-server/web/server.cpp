/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/server.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

static const char HTML_HOME_PAGE[] = R"HTML(<!DOCTYPE html>
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

using fptn::web::Server;

Server::Server(std::uint16_t port,
    const fptn::nat::TableSPtr& nat_table,
    const fptn::user::UserManagerSPtr& user_manager,
    const fptn::common::jwt_token::TokenManagerSPtr& token_manager,
    const fptn::statistic::MetricsSPtr& prometheus,
    const std::string& prometheus_access_key,
    const pcpp::IPv4Address& dns_server_ipv4,
    const pcpp::IPv6Address& dns_server_ipv6,
    int thread_number)
    : running_(false),
      port_(port),
      nat_table_(nat_table),
      user_manager_(user_manager),
      token_manager_(token_manager),
      prometheus_(prometheus),
      prometheus_access_key_(prometheus_access_key),
      dns_server_ipv4_(dns_server_ipv4),
      dns_server_ipv6_(dns_server_ipv6),
      thread_number_(std::max<std::size_t>(1, thread_number)),
      ioc_(thread_number),
      from_client_(std::make_unique<fptn::common::data::Channel>()),
      to_client_(std::make_unique<fptn::common::data::ChannelAsync>(ioc_)) {
  using std::placeholders::_1;
  using std::placeholders::_2;
  using std::placeholders::_3;
  using std::placeholders::_4;
  using std::placeholders::_5;
  using std::placeholders::_6;
  using std::placeholders::_7;

  listener_ = std::make_shared<Listener>(ioc_, port_, token_manager,
      std::bind(
          &Server::HandleWsOpenConnection, this, _1, _2, _3, _4, _5, _6, _7),
      std::bind(&Server::HandleWsNewIPPacket, this, _1),
      std::bind(&Server::HandleWsCloseConnection, this, _1));
  listener_->httpRegister(
      kUrlHome_, "GET", std::bind(&Server::HandleApiHome, this, _1, _2));
  listener_->httpRegister(
      kUrlDns_, "GET", std::bind(&Server::HandleApiDns, this, _1, _2));
  listener_->httpRegister(
      kUrlLogin_, "POST", std::bind(&Server::HandleApiLogin, this, _1, _2));
  listener_->httpRegister(kUrlTestFileBin_, "GET",
      std::bind(&Server::HandleApiTestFile, this, _1, _2));
  if (!prometheus_access_key.empty()) {
    // Construct the URL for accessing Prometheus statistics by appending the
    // access key
    const std::string metrics = kUrlMetrics_ + '/' + prometheus_access_key;
    listener_->httpRegister(
        metrics, "GET", std::bind(&Server::HandleApiMetrics, this, _1, _2));
  }
}

Server::~Server() { Stop(); }

bool Server::Start() noexcept {
  running_ = true;
  try {
    // run listener
    boost::asio::co_spawn(
        ioc_,
        [this]() -> boost::asio::awaitable<void> { co_await listener_->run(); },
        boost::asio::detached);
    // run senders
    for (std::size_t i = 0; i < 1; i++) {
      boost::asio::co_spawn(
          ioc_,
          [this]() -> boost::asio::awaitable<void> { co_await RunSender(); },
          boost::asio::detached);
    }
    // run threads
    ioc_threads_.reserve(thread_number_);
    for (std::size_t i = 0; i < thread_number_; ++i) {
      ioc_threads_.emplace_back([this]() { ioc_.run(); });
    }
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Server::start error: {}", err.what());
    running_ = false;
    return false;
  }
  return true;
}

boost::asio::awaitable<void> Server::RunSender() {
  const std::chrono::milliseconds timeout{1};

  while (running_) {
    auto optpacket = co_await to_client_->WaitForPacketAsync(timeout);
    if (optpacket && running_) {
      SessionSPtr session;

      {  // mutex
        const std::unique_lock<std::mutex> lock(mutex_);

        auto it = sessions_.find(optpacket->get()->ClientId());
        if (it != sessions_.end()) {
          session = it->second;
        }
      }

      if (session) {
        const bool status = co_await session->Send(std::move(*optpacket));
        if (!status) {
          session->Close();
        }
      }
    }
  }
  co_return;
}

bool Server::Stop() noexcept {
  running_ = false;
  SPDLOG_INFO("Server stop");

  for (auto& session : sessions_) {
    session.second->Close();
  }

  {
    const std::unique_lock<std::mutex> lock(mutex_);
    sessions_.clear();
  }

  ioc_.stop();
  for (auto& th : ioc_threads_) {
    if (th.joinable()) {
      th.join();
    }
  }
  return true;
}

void Server::Send(fptn::common::network::IPPacketPtr packet) noexcept {
  to_client_->Push(std::move(packet));
}

fptn::common::network::IPPacketPtr Server::WaitForPacket(
    const std::chrono::milliseconds& duration) noexcept {
  return from_client_->waitForPacket(duration);
}

int Server::HandleApiHome(
    const http::request& req, http::response& resp) noexcept {
  (void)req;

  resp.body() = HTML_HOME_PAGE;
  resp.set(boost::beast::http::field::content_type, "text/html; charset=utf-8");
  return 200;
}

int Server::HandleApiDns(
    const http::request& req, http::response& resp) noexcept {
  (void)req;

  resp.body() = fmt::format(R"({{"dns": "{}", "dns_ipv6": "{}" }})",
      dns_server_ipv4_.toString(), dns_server_ipv6_.toString());
  resp.set(boost::beast::http::field::content_type,
      "application/json; charset=utf-8");
  return 200;
}

int Server::HandleApiLogin(
    const http::request& req, http::response& resp) noexcept {
  try {
    auto request = nlohmann::json::parse(req.body());
    const auto username = request.at("username").get<std::string>();
    const auto password = request.at("password").get<std::string>();
    int bandwidthBit = 0;
    if (user_manager_->Login(username, password, bandwidthBit)) {
      SPDLOG_INFO("Successful login for user {}", username);
      const auto tokens = token_manager_->Generate(username, bandwidthBit);
      resp.body() = fmt::format(
          R"({{ "access_token": "{}", "refresh_token": "{}", "bandwidth_bit": {} }})",
          tokens.first, tokens.second, std::to_string(bandwidthBit));
      return 200;
    }
    spdlog::warn("Wrong password for user: \"{}\" ", username);
    resp.body() =
        R"({"status": "error", "message": "Invalid login or password."})";
  } catch (const nlohmann::json::exception& e) {
    SPDLOG_ERROR("HTTP JSON AUTH ERROR: {}", e.what());
    resp.body() = R"({"status": "error", "message": "Invalid JSON format."})";
    return 400;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("HTTP AUTH ERROR: {}", e.what());
    resp.body() =
        R"({"status": "error", "message": "An unexpected error occurred."})";
    return 500;
  } catch (...) {
    SPDLOG_ERROR("UNDEFINED SERVER ERROR");
    resp.body() = R"({"status": "error", "message": "Undefined server error"})";
    return 501;
  }
  return 401;
}

int Server::HandleApiMetrics(
    const http::request& req, http::response& resp) noexcept {
  (void)req;

  resp.set(boost::beast::http::field::content_type, "text/html; charset=utf-8");
  resp.body() = prometheus_->Collect();
  return 200;
}

int Server::HandleApiTestFile(
    const http::request& req, http::response& resp) noexcept {
  (void)req;

  static const std::string data =
      fptn::common::utils::GenerateRandomString(100 * 1024);  // 100KB

  resp.set(boost::beast::http::field::content_type, "application/octet-stream");
  resp.body() = data;
  return 200;
}

bool Server::HandleWsOpenConnection(fptn::ClientID client_id,
    const pcpp::IPv4Address& client_ip,
    const pcpp::IPv4Address& client_vpn_ipv4,
    const pcpp::IPv6Address& client_vpn_ipv6,
    const SessionSPtr& session,
    const std::string& url,
    const std::string& access_token) noexcept {
  if (url != kUrlWebSocket_) {
    SPDLOG_ERROR("Wrong URL \"{}\"", url);
    return false;
  }
  if (client_vpn_ipv4 != pcpp::IPv4Address("") &&
      client_vpn_ipv6 != pcpp::IPv6Address("")) {
    std::string username;
    std::size_t bandwidth_bites_seconds = 0;
    if (token_manager_->Validate(
            access_token, username, bandwidth_bites_seconds)) {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      if (sessions_.find(client_id) == sessions_.end()) {
        const auto shaper_to_client =
            std::make_shared<fptn::traffic_shaper::LeakyBucket>(
                bandwidth_bites_seconds);
        const auto shaper_from_client =
            std::make_shared<fptn::traffic_shaper::LeakyBucket>(
                bandwidth_bites_seconds);
        const auto nat_session = nat_table_->CreateClientSession(client_id,
            username, client_vpn_ipv4, client_vpn_ipv6, shaper_to_client,
            shaper_from_client);
        SPDLOG_INFO(
            "NEW SESSION! Username={} ClientId={} Bandwidth={} ClientIP={} "
            "VirtualIPv4={} VirtualIPv6={}",
            username, client_id, bandwidth_bites_seconds, client_ip.toString(),
            nat_session->FakeClientIPv4().toString(),
            nat_session->FakeClientIPv6().toString());
        sessions_.insert({client_id, session});
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

void Server::HandleWsNewIPPacket(
    fptn::common::network::IPPacketPtr packet) noexcept {
  from_client_->push(std::move(packet));
}

void Server::HandleWsCloseConnection(fptn::ClientID clientId) noexcept {
  SessionSPtr session;
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    auto it = sessions_.find(clientId);
    if (it != sessions_.end()) {
      session = std::move(it->second);
      sessions_.erase(it);
    }
  }
  if (session != nullptr) {
    session->Close();
    SPDLOG_INFO("DEL SESSION! clientId={}", clientId);
  }
  nat_table_->DelClientSession(clientId);
}
