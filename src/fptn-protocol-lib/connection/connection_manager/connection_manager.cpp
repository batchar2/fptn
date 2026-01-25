/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "connection_manager.h"

#include <memory>
#include <string>
#include <utility>

#include <boost/process/v1/io.hpp>
#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/connection/connection_manager_builder/connection_manager_builder.h"
#include "fptn-protocol-lib/connection/strategies/long_term_connection/long_term_connection.h"
#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/connection_config.h"

namespace fptn::protocol::connection {

using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;
using fptn::protocol::https::ApiClient;

ConnectionManager::ConnectionManager(
    strategies::ConnectionStrategy connection_strategy_type,
    fptn::protocol::https::ConnectionConfig config)
    : running_(false),
      reconnection_attempts_(0),
      connection_strategy_type_(connection_strategy_type),
      config_(std::move(config)) {}

ConnectionManager::~ConnectionManager() {
  if (strategy_connection_) {
    strategy_connection_->Stop();
    strategy_connection_.reset();
  }
}

void ConnectionManager::SetRecvIPPacketCallback(
    const fptn::protocol::https::RecvIPPacketCallback& callback) {
  config_.common.recv_ip_packet_callback = callback;
}

bool ConnectionManager::Login(
    const std::string& username, const std::string& password, int timeout_sec) {
  const std::string request = fmt::format(
      R"({{ "username": "{}", "password": "{}" }})", username, password);

  const std::string ip = config_.common.server_ip.ToString();
  ApiClient cli(ip, config_.common.server_port, config_.common.sni,
      config_.common.md5_fingerprint,
      config_.common.https_init_connection_strategy);

  const auto resp =
      cli.Post("/api/v1/login", request, "application/json", timeout_sec);
  if (resp.code == 200) {
    try {
      const auto msg = resp.Json();
      if (!msg.contains("access_token")) {
        SPDLOG_ERROR(
            "Error: Access token not found in the response. Check your "
            "conection");
      } else {
        jwt_access_token_ = msg["access_token"];
        SPDLOG_INFO("Login successful");
        return true;
      }
    } catch (const nlohmann::json::parse_error& e) {
      latest_error_ = e.what();
      SPDLOG_ERROR("Error parsing JSON response: {} ", e.what());
    } catch (const std::exception& ex) {
      latest_error_ = ex.what();
      SPDLOG_ERROR("Exception: {}", ex.what());
    }
  } else {
    latest_error_ = resp.errmsg;
    SPDLOG_ERROR(
        "Error: Request failed code: {} msg: {}", resp.code, resp.errmsg);
  }
  return false;
}

std::pair<IPv4Address, IPv6Address> ConnectionManager::GetDns() {
  const std::string ip = config_.common.server_ip.ToString();
  ApiClient cli(ip, config_.common.server_port, config_.common.sni,
      config_.common.md5_fingerprint,
      config_.common.https_init_connection_strategy);

  const auto resp = cli.Get("/api/v1/dns");
  if (resp.code == 200) {
    try {
      const auto msg = resp.Json();
      if (!msg.contains("dns")) {
        SPDLOG_ERROR(
            "Error: dns not found in the response. Check your connection");
      } else {
        const std::string dns_ipv4 = msg["dns"];
        const std::string dns_ipv6 =
            (msg.contains("dns_ipv6") ? msg["dns_ipv6"]
                                      : FPTN_SERVER_DEFAULT_ADDRESS_IP6);
        return {IPv4Address(dns_ipv4), IPv6Address(dns_ipv6)};
      }
    } catch (const nlohmann::json::parse_error& e) {
      latest_error_ = e.what();
      SPDLOG_ERROR("Error parsing JSON response: {}", e.what());
    } catch (const std::exception& ex) {
      latest_error_ = ex.what();
      SPDLOG_ERROR("Exception: {}", ex.what());
    }
  } else {
    latest_error_ = resp.errmsg;
    SPDLOG_ERROR(
        "Error: Request failed code: {} msg: {}", resp.code, resp.errmsg);
  }
  return {IPv4Address(), IPv6Address()};
}

bool ConnectionManager::Start() {
  running_ = true;
  th_ = std::thread(&ConnectionManager::Run, this);
  return th_.joinable();
}

bool ConnectionManager::Stop() {
  if (!running_) {
    return false;
  }

  SPDLOG_INFO("Stopping client");
  {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (!running_) {  // Double-check after acquiring lock
      return false;
    }
    running_ = false;
  }

  if (strategy_connection_) {
    strategy_connection_->Stop();
    strategy_connection_.reset();
  }

  if (th_.joinable()) {
    try {
      th_.join();
    } catch (...) {
      SPDLOG_WARN("Unexpected exception during thread join");
    }
  }
  return true;
}

bool ConnectionManager::Send(fptn::common::network::IPPacketPtr packet) const {
  try {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (strategy_connection_ && running_) {
      strategy_connection_->Send(std::move(packet));
      return true;
    }
  } catch (const std::runtime_error& err) {
    SPDLOG_ERROR("Send error: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception occurred: {}", e.what());
  }
  return false;
}

bool ConnectionManager::IsStarted() const {
  return running_ && strategy_connection_;
}

const std::string& ConnectionManager::LatestError() const {
  return latest_error_;
}

void ConnectionManager::Run() {
  // Time window for counting attempts (1 minute)
  constexpr auto kReconnectionWindow = std::chrono::seconds(120);
  // Delay between reconnection attempts
  constexpr auto kReconnectionDelay = std::chrono::milliseconds(300);

  // Current count of reconnection attempts
  reconnection_attempts_ = 0;
  auto window_start_time = std::chrono::steady_clock::now();

  const auto max_reconnection = config_.common.max_reconnections;
  while (running_ && reconnection_attempts_ < max_reconnection) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      // cppcheck-suppress identicalInnerCondition
      if (running_ && connection_strategy_type_ ==
                          strategies::ConnectionStrategy::kLongTermConnection) {
        strategy_connection_ =
            strategies::LongTermConnection::Create(jwt_access_token_, config_);
      }
    }

    if (running_ && strategy_connection_) {
      strategy_connection_->Start();  // Start the WebSocket client
    }

    if (!running_) {
      break;
    }

    // clean
    if (strategy_connection_) {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      // cppcheck-suppress knownConditionTrueFalse
      if (strategy_connection_ && running_) {
        strategy_connection_->Stop();
        strategy_connection_.reset();
      }
    }

    // Calculate time since last window start
    const auto current_time = std::chrono::steady_clock::now();
    const auto elapsed = current_time - window_start_time;

    // Reconnection attempt counting logic
    if (elapsed >= kReconnectionWindow) {
      // Reset counter if we're past the time window
      reconnection_attempts_ = 0;
      window_start_time = current_time;
    } else {
      ++reconnection_attempts_;  // Decrement counter if within time window
    }

    // Log connection failure and wait before retrying
    SPDLOG_ERROR(
        "Connection closed (attempt {}/{} in current window). Reconnecting in "
        "{}ms...",
        reconnection_attempts_, max_reconnection, kReconnectionDelay.count());

    std::this_thread::sleep_for(kReconnectionDelay);
  }

  if (running_ && !reconnection_attempts_) {
    SPDLOG_ERROR("Connection failure: Could not establish connection");
  }
}

}  // namespace fptn::protocol::connection
