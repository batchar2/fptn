/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "http/client.h"

#include <memory>
#include <string>
#include <utility>

#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/https_client.h"
#include "routing/iptables.h"

using fptn::http::Client;
using fptn::protocol::https::HttpsClient;

Client::Client(pcpp::IPv4Address server_ip,
    int server_port,
    pcpp::IPv4Address tun_interface_address_ipv4,
    pcpp::IPv6Address tun_interface_address_ipv6,
    std::string sni,
    std::string md5_fingerprint,
    NewIPPacketCallback new_ip_pkt_callback)
    : running_(false),
      server_ip_(std::move(server_ip)),
      server_port_(server_port),
      tun_interface_address_ipv4_(std::move(tun_interface_address_ipv4)),
      tun_interface_address_ipv6_(std::move(tun_interface_address_ipv6)),
      sni_(std::move(sni)),
      md5_fingerprint_(std::move(md5_fingerprint)),
      new_ip_pkt_callback_(std::move(new_ip_pkt_callback)),
      reconnection_attempts_(kMaxReconnectionAttempts_) {}

bool Client::Login(const std::string& username, const std::string& password) {
  const std::string request = fmt::format(
      R"({{ "username": "{}", "password": "{}" }})", username, password);
  HttpsClient cli(server_ip_.toString(), server_port_, sni_, md5_fingerprint_);
  const auto resp = cli.Post("/api/v1/login", request, "application/json");
  if (resp.code == 200) {
    try {
      const auto msg = resp.Json();
      if (!msg.contains("access_token")) {
        SPDLOG_ERROR(
            "Error: Access token not found in the response. Check your "
            "conection");
      } else {
        access_token_ = msg["access_token"];
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

std::pair<pcpp::IPv4Address, pcpp::IPv6Address> Client::GetDns() {
  SPDLOG_INFO("Obtained DNS server address. Connecting to {}:{}",
      server_ip_.toString(), server_port_);

  HttpsClient cli(server_ip_.toString(), server_port_, sni_, md5_fingerprint_);
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
        return {pcpp::IPv4Address(dns_ipv4), pcpp::IPv6Address(dns_ipv6)};
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
  return {pcpp::IPv4Address(), pcpp::IPv6Address()};
}

void Client::SetRecvIPPacketCallback(
    const NewIPPacketCallback& callback) noexcept {
  new_ip_pkt_callback_ = callback;
}

bool Client::Send(fptn::common::network::IPPacketPtr packet) {
  try {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (ws_ && running_) {
      ws_->Send(std::move(packet));
      return true;
    }
  } catch (const std::runtime_error& err) {
    SPDLOG_ERROR("Send error: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception occurred: {}", e.what());
  }
  return false;
}

void Client::Run() {
  // Time window for counting attempts (1 minute)
  constexpr auto kReconnectionWindow = std::chrono::seconds(120);
  // Delay between reconnection attempts
  constexpr auto kReconnectionDelay = std::chrono::milliseconds(300);

  // Current count of reconnection attempts
  reconnection_attempts_ = kMaxReconnectionAttempts_;
  auto window_start_time = std::chrono::steady_clock::now();

  while (running_ && reconnection_attempts_) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      // cppcheck-suppress identicalInnerCondition
      if (running_) {  // Double-check after acquiring lock
        ws_ = std::make_shared<fptn::protocol::websocket::WebsocketClient>(
            server_ip_, server_port_, tun_interface_address_ipv4_,
            tun_interface_address_ipv6_, new_ip_pkt_callback_, sni_,
            access_token_, md5_fingerprint_);
      }
    }

    if (running_ && ws_) {
      ws_->Run();  // Start the WebSocket client
    }
    if (!running_) {
      break;
    }

    // Calculate time since last window start
    auto current_time = std::chrono::steady_clock::now();
    auto elapsed = current_time - window_start_time;

    // Reconnection attempt counting logic
    if (elapsed >= kReconnectionWindow) {
      // Reset counter if we're past the time window
      reconnection_attempts_ = kMaxReconnectionAttempts_;
      window_start_time = current_time;
    } else {
      --reconnection_attempts_;  // Decrement counter if within time window
    }

    // Log connection failure and wait before retrying
    SPDLOG_ERROR(
        "Connection closed (attempt {}/{} in current window). Reconnecting in "
        "{}ms...",
        kMaxReconnectionAttempts_ - reconnection_attempts_,
        kMaxReconnectionAttempts_, kReconnectionDelay.count());

    std::this_thread::sleep_for(kReconnectionDelay);
  }
  if (running_ && !reconnection_attempts_) {
    SPDLOG_ERROR("Connection failure: Could not establish connection");
  }
}

bool Client::Start() {
  running_ = true;
  th_ = std::thread(&Client::Run, this);
  return th_.joinable();
}

bool Client::Stop() {
  if (!running_) {
    return false;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // cppcheck-suppress identicalConditionAfterEarlyExit
  if (!running_) {  // Double-check after acquiring lock
    return false;
  }

  running_ = false;
  if (ws_) {
    ws_->Stop();
    ws_.reset();
  }
  if (th_.joinable()) {
    th_.join();
  }
  return true;
}

bool Client::IsStarted() {
  if (!running_) {
    return false;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return running_ && ws_ && reconnection_attempts_ > 0;
}

const std::string& Client::LatestError() const { return latest_error_; }
