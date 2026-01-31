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
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

using fptn::web::Server;

Server::Server(std::uint16_t port,
    const fptn::nat::TableSPtr& nat_table,
    const fptn::user::UserManagerSPtr& user_manager,
    const fptn::common::jwt_token::TokenManagerSPtr& token_manager,
    const fptn::statistic::MetricsSPtr& prometheus,
    const std::string& prometheus_access_key,
    fptn::common::network::IPv4Address dns_server_ipv4,
    fptn::common::network::IPv6Address dns_server_ipv6,
    bool enable_detect_probing,
    std::string default_proxy_domain,
    std::vector<std::string> allowed_sni_list,
    std::size_t max_active_sessions_per_user,
    std::string server_external_ips,
    int thread_number)
    : running_(false),
      port_(port),
      nat_table_(nat_table),
      user_manager_(user_manager),
      token_manager_(token_manager),
      prometheus_(prometheus),
      prometheus_access_key_(prometheus_access_key),
      dns_server_ipv4_(std::move(dns_server_ipv4)),
      dns_server_ipv6_(std::move(dns_server_ipv6)),
      enable_detect_probing_(enable_detect_probing),
      default_proxy_domain_(std::move(default_proxy_domain)),
      allowed_sni_list_(std::move(allowed_sni_list)),
      max_active_sessions_per_user_(max_active_sessions_per_user),
      server_external_ips_(std::move(server_external_ips)),
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

  handshake_cache_manager_ = std::make_shared<HandshakeCacheManager>(ioc_);

  listener_ = std::make_shared<Listener>(port_,
      // proxy settings
      enable_detect_probing_, default_proxy_domain_, allowed_sni_list_,
      // ioc
      ioc_, token_manager, handshake_cache_manager_, server_external_ips_,
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleWsOpenConnection, this, _1, _2),
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleWsNewIPPacket, this, _1),
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleWsCloseConnection, this, _1));

  listener_->AddApiHandle(
      // NOLINTNEXTLINE(modernize-avoid-bind)
      kUrlDns_, "GET", std::bind(&Server::HandleApiDns, this, _1, _2));

  listener_->AddApiHandle(
      // NOLINTNEXTLINE(modernize-avoid-bind)
      kUrlLogin_, "POST", std::bind(&Server::HandleApiLogin, this, _1, _2));

  listener_->AddApiHandle(kUrlTestFileBin_, "GET",
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&Server::HandleApiTestFile, this, _1, _2));

  if (!prometheus_access_key.empty()) {
    // Construct the URL for accessing Prometheus statistics by appending the
    // access key
    const std::string metrics = kUrlMetrics_ + '/' + prometheus_access_key;
    listener_->AddApiHandle(
        // NOLINTNEXTLINE(modernize-avoid-bind)
        metrics, "GET", std::bind(&Server::HandleApiMetrics, this, _1, _2));
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
    // run senders
    boost::asio::co_spawn(
        ioc_,
        [this]() -> boost::asio::awaitable<void> { co_await RunSender(); },
        boost::asio::detached);
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
  constexpr std::chrono::milliseconds kTimeout{10};

  while (running_) {
    auto optpacket = co_await to_client_->WaitForPacketAsync(kTimeout);
    if (optpacket && running_) {
      ClientEndpointSPtr session;

      {
        const std::unique_lock<std::mutex> lock(mutex_);  // mutex

        auto it = client_endpoints_.find(optpacket->get()->ClientId());
        if (it != client_endpoints_.end()) {
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

bool Server::Stop() {
  if (running_) {
    running_ = false;
    SPDLOG_INFO("Server stop");

    listener_->Stop();

    for (auto& session : client_endpoints_) {
      if (session.second) {
        session.second->Close();
      }
    }
    client_endpoints_.clear();
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

void Server::Send(fptn::common::network::IPPacketPtr packet) {
  to_client_->Push(std::move(packet));
}

fptn::common::network::IPPacketPtr Server::WaitForPacket(
    const std::chrono::milliseconds& duration) {
  return from_client_->WaitForPacket(duration);
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
int Server::HandleApiDns(const http::request& req, http::response& resp) {
  (void)req;

  resp.body() = fmt::format(R"({{"dns": "{}", "dns_ipv6": "{}" }})",
      dns_server_ipv4_.ToString(), dns_server_ipv6_.ToString());
  resp.set(boost::beast::http::field::content_type,
      "application/json; charset=utf-8");
  return 200;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
int Server::HandleApiLogin(const http::request& req, http::response& resp) {
  try {
    const auto request = nlohmann::json::parse(req.body());
    const auto username = request.at("username").get<std::string>();
    const auto password = request.at("password").get<std::string>();
    int bandwidth_bit = 0;
    if (user_manager_->Login(username, password, bandwidth_bit)) {
      SPDLOG_INFO("Successful login for user {}", username);
      const auto tokens = token_manager_->Generate(username, bandwidth_bit);
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

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
int Server::HandleApiMetrics(const http::request& req, http::response& resp) {
  (void)req;

  resp.set(boost::beast::http::field::content_type, "text/html; charset=utf-8");
  resp.body() = prometheus_->Collect();
  return 200;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
int Server::HandleApiTestFile(const http::request& req, http::response& resp) {
  (void)req;

  static const std::string kData =
      fptn::common::utils::GenerateRandomString(100 * 1024);  // 100KB

  resp.set(boost::beast::http::field::content_type, "application/octet-stream");
  resp.body() = kData;
  return 200;
}

bool Server::HandleWsOpenConnection(
    const fptn::nat::ConnectParams& params, const ClientEndpointSPtr& session) {
  if (!running_) {
    SPDLOG_ERROR("Server is not running");
    return false;
  }
  if (params.request.url != kUrlWebSocket_) {
    SPDLOG_ERROR("Wrong URL \"{}\"", params.request.url);
    return false;
  }

  if (client_endpoints_.contains(params.client_id)) {
    SPDLOG_WARN("Client with same ID already exists!");
    return false;
  }

  if (!params.Validate()) {
    SPDLOG_WARN("Wrong request: {}", params.client_id);
  }

  std::string username;
  std::size_t bandwidth_bites_seconds = 0;
  // get username and bandwidth from a jwt-token
  if (!token_manager_->Validate(
          params.request.jwt_auth_token, username, bandwidth_bites_seconds)) {
    SPDLOG_WARN("WRONG TOKEN: {}", username);
    return false;
  }

  fptn::nat::ConnectParams mod_params = params;
  mod_params.user.username = username;
  mod_params.user.bandwidth_bites_seconds += bandwidth_bites_seconds;

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  const auto active_sessions =
      nat_table_->GetNumberActiveSessionByUsername(username);

  if (active_sessions > max_active_sessions_per_user_) {
    SPDLOG_WARN("Session limit exceeded for user '{}': {} active (limit: {})",
        username, active_sessions, max_active_sessions_per_user_);
    return false;
  }

  const auto connection_multiplexer = nat_table_->AddConnection(mod_params);
  if (!connection_multiplexer) {
    return false;
  }

  SPDLOG_INFO(
      "New session: username={} client_id={} Bandwidth={} ClientIP={} "
      "VirtualIPv4={} VirtualIPv6={}",
      mod_params.user.username, mod_params.client_id,
      mod_params.user.bandwidth_bites_seconds,
      mod_params.request.client_ipv4.ToString(),
      connection_multiplexer->FakeClientIPv4().ToString(),
      connection_multiplexer->FakeClientIPv6().ToString());
  if (running_) {
    client_endpoints_.insert({mod_params.client_id, session});
    return true;
  }
  return false;
}

void Server::HandleWsNewIPPacket(
    fptn::common::network::IPPacketPtr packet) noexcept {
  from_client_->Push(std::move(packet));
}

void Server::HandleWsCloseConnection(fptn::ClientID client_id) noexcept {
  ClientEndpointSPtr session;
  if (running_) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    auto it = client_endpoints_.find(client_id);
    if (it != client_endpoints_.end()) {
      session = std::move(it->second);
      client_endpoints_.erase(it);
    }
  }
  if (session != nullptr) {
    session->Close();
    SPDLOG_INFO("Session closed and removed (client_id={})", client_id);
  } else {
    SPDLOG_WARN(
        "Attempted to close non-existent session (client_id={})", client_id);
  }
  nat_table_->DelConnectionByClientId(client_id);
}
