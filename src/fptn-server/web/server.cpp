/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/server.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/api/handle.h"
#include "common/utils/utils.h"

namespace fptn::web {
Server::Server(Config config, int thread_number)
    : running_(false),
      config_(std::move(config)),
      thread_number_(std::max<std::size_t>(1, thread_number)),
      ioc_(thread_number),
      from_client_(std::make_unique<fptn::common::data::Channel>()) {
  handshake_cache_manager_ = std::make_shared<HandshakeCacheManager>(
      ioc_, config_.server_params->DefaultProxyDomain());

  listener_ = std::make_shared<Listener>(Listener::Config{.port = config_.port,
      .enable_detect_probing = config_.server_params->EnableDetectProbing(),
      .default_proxy_domain = config_.server_params->DefaultProxyDomain(),
      .allowed_sni_list = config_.server_params->AllowedSniList(),
      .ioc = ioc_,
      .token_manager = config_.token_manager,
      .handshake_cache_manager = handshake_cache_manager_,
      .server_external_ips = config_.server_params->ServerExternalIPs(),
      .on_ws_open_callback =
          [this](auto&& param1, auto&& param2, auto&& param3, auto&& param4,
              auto&& param5, auto&& param6, auto&& param7) {
            return HandleWsOpenConnection(
                std::forward<decltype(param1)>(param1),
                std::forward<decltype(param2)>(param2),
                std::forward<decltype(param3)>(param3),
                std::forward<decltype(param4)>(param4),
                std::forward<decltype(param5)>(param5),
                std::forward<decltype(param6)>(param6),
                std::forward<decltype(param7)>(param7));
          },

      .on_ws_new_ip_packet_callback =
          [this](auto&& param) {
            return HandleWsNewIPPacket(std::forward<decltype(param)>(param));
          },

      .on_ws_close_callback =
          [this](auto&& param) {
            return HandleWsCloseConnection(
                std::forward<decltype(param)>(param));
          }});

  if (!config_.server_params->PrometheusAccessKey().empty()) {
    // Construct the URL for accessing Prometheus statistics by appending the
    // access key
    const std::string metrics = std::string(common::api::kApiMetricsUrl) + '/' +
                                config_.server_params->PrometheusAccessKey();

    listener_->AddApiHandle(
        metrics, "GET", [this](auto&& param1, auto&& param2) {
          return HandleApiMetrics(std::forward<decltype(param1)>(param1),
              std::forward<decltype(param2)>(param2));
        });
  }
}

Server::~Server() { Stop(); }

bool Server::Start() {
  running_ = true;
  try {
    // run listener
    boost::asio::co_spawn(
        ioc_,
        [this]() -> boost::asio::awaitable<void> { co_await listener_->Run(); },
        boost::asio::detached);
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

bool Server::Stop() {
  if (running_) {
    running_ = false;
    SPDLOG_INFO("Server stop");

    listener_->Stop();

    const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

    for (auto& session : sessions_) {
      if (session.second) {
        session.second->Close();
      }
    }
    sessions_.clear();
    if (!ioc_.stopped()) {
      ioc_.stop();
    }
    for (auto& th : ioc_threads_) {
      if (th.joinable()) {
        th.join();
      }
    }
    return true;
  }
  return false;
}

fptn::web::SessionSPtr Server::GetSessionById(fptn::ClientID client_id) {
  const std::shared_lock<std::shared_mutex> lock(mutex_);  // mutex

  auto it = sessions_.find(client_id);
  if (it != sessions_.end()) {
    return it->second;
  }
  return nullptr;
}

fptn::common::network::BatchIPPacketPtr Server::WaitForPackets(
    const std::chrono::milliseconds& duration) {
  return from_client_->WaitForPackets(duration);
}

int Server::HandleApiDns(const http::request& req, http::response& resp) const {
  (void)req;

  resp.body() = fmt::format(R"({{"dns": "{}", "dns_ipv6": "{}" }})",
      config_.server_params->TunInterfaceIPv4().ToString(),
      config_.server_params->TunInterfaceIPv6().ToString());
  resp.set(boost::beast::http::field::content_type,
      "application/json; charset=utf-8");
  return 200;
}

int Server::HandleApiLogin(
    const http::request& req, http::response& resp) const {
  try {
    const auto request = nlohmann::json::parse(req.body());
    const auto username = request.at("username").get<std::string>();
    const auto password = request.at("password").get<std::string>();
    int bandwidth_bit = 0;
    if (config_.user_manager->Login(username, password, bandwidth_bit)) {
      SPDLOG_INFO("Successful login for user {}", username);
      const auto tokens =
          config_.token_manager->Generate(username, bandwidth_bit);
      resp.body() = fmt::format(
          R"({{ "access_token": "{}", "refresh_token": "{}", "bandwidth_bit": {} }})",
          tokens.first, tokens.second, std::to_string(bandwidth_bit));
      return 200;
    }
    SPDLOG_WARN("Wrong password for user: \"{}\" ", username);
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
    const http::request& req, http::response& resp) const {
  (void)req;

  resp.set(boost::beast::http::field::content_type, "text/html; charset=utf-8");
  resp.body() = config_.prometheus->Collect();
  return 200;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
int Server::HandleApiTestFile(
    const http::request& req, http::response& resp) const {
  (void)req;

  static const std::string kData =
      fptn::common::utils::GenerateRandomString(100 * 1024);  // 100KB

  resp.set(boost::beast::http::field::content_type, "application/octet-stream");
  resp.body() = kData;
  return 200;
}

fptn::client::SessionSPtr Server::HandleWsOpenConnection(
    fptn::ClientID client_id,
    const fptn::common::network::IPv4Address& client_ip,
    const fptn::common::network::IPv4Address& client_vpn_ipv4,
    const fptn::common::network::IPv6Address& client_vpn_ipv6,
    const SessionSPtr& session,
    const std::string& url,
    const std::string& access_token) {
  if (!running_) {
    SPDLOG_ERROR("Server is not running");
    return nullptr;
  }
  if (url != fptn::common::api::kApiWebSocketUrlOld &&
      url != fptn::common::api::kApiWebSocketUrl) {
    SPDLOG_ERROR("Wrong URL \"{}\"", url);
    return nullptr;
  }

  std::string username;
  std::size_t bandwidth_bites_seconds = 0;
  if (!config_.token_manager->Validate(
          access_token, username, bandwidth_bites_seconds)) {
    SPDLOG_WARN("WRONG TOKEN: {}", username);
    return nullptr;
  }

  const std::unique_lock<std::shared_mutex> lock(mutex_);  // mutex

  const auto active_sessions =
      config_.nat_table->GetNumberActiveSessionByUsername(username);

  if (active_sessions > config_.server_params->MaxActiveSessionsPerUser()) {
    SPDLOG_WARN("Session limit exceeded for user '{}': {} active (limit: {})",
        username, active_sessions,
        config_.server_params->MaxActiveSessionsPerUser());
    return nullptr;
  }

  if (sessions_.contains(client_id)) {
    SPDLOG_WARN("Client with same ID already exists!");
    return nullptr;
  }

  const auto shaper_to_client =
      std::make_shared<fptn::traffic_shaper::LeakyBucket>(
          bandwidth_bites_seconds);
  const auto shaper_from_client =
      std::make_shared<fptn::traffic_shaper::LeakyBucket>(
          bandwidth_bites_seconds);

  fptn::client::SessionSPtr nat_session = nullptr;
  if (!client_vpn_ipv4.IsEmpty() && !client_vpn_ipv6.IsEmpty()) {
    // deprecated
    nat_session = config_.nat_table->CreateClientSession(client_id, username,
        client_vpn_ipv4, client_vpn_ipv6, shaper_to_client, shaper_from_client);
  } else {
    nat_session = config_.nat_table->CreateClientSession2(
        client_id, username, shaper_to_client, shaper_from_client);
  }

  SPDLOG_INFO(
      "NEW SESSION! Username={} client_id={} Bandwidth={} ClientIP={} "
      "VPN_IPv4={} VPN_IPv6={} URL={}",
      username, client_id, bandwidth_bites_seconds, client_ip.ToString(),
      nat_session->FakeClientIPv4().ToString(),
      nat_session->FakeClientIPv6().ToString(), url);

  if (running_) {
    sessions_.insert({client_id, session});
    return nat_session;
  }
  return nullptr;
}

void Server::HandleWsNewIPPacket(
    fptn::common::network::IPPacketPtr packet) noexcept {
  from_client_->Push(std::move(packet));
}

void Server::HandleWsCloseConnection(fptn::ClientID client_id) noexcept {
  SessionSPtr session;
  if (running_) {
    const std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = sessions_.find(client_id);
    if (it != sessions_.end()) {
      session = std::move(it->second);
      sessions_.erase(it);
    }
  }
  if (session != nullptr) {
    session->Close();
    SPDLOG_INFO("Session closed and removed (client_id={})", client_id);
  } else {
    SPDLOG_WARN(
        "Attempted to close non-existent session (client_id={})", client_id);
  }
  config_.nat_table->DelClientSession(client_id);
}
}  // namespace fptn::web
