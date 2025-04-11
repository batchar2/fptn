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

#include "routing//iptables.h"

using fptn::http::Client;

Client::Client(const pcpp::IPv4Address& server_ip,
    int server_port,
    const pcpp::IPv4Address& tun_interface_address_ipv4,
    const pcpp::IPv6Address& tun_interface_address_ipv6,
    const std::string& sni,
    const NewIPPacketCallback& new_ip_pkt_callback)
    : running_(false),
      server_ip_(server_ip),
      server_port_(server_port),
      tun_interface_address_ipv4_(tun_interface_address_ipv4),
      tun_interface_address_ipv6_(tun_interface_address_ipv6),
      sni_(sni),
      new_ip_pkt_callback_(new_ip_pkt_callback) {}

bool Client::Login(
    const std::string& username, const std::string& password) noexcept {
  const std::string request = fmt::format(
      R"({{ "username": "{}", "password": "{}" }})", username, password);

  fptn::common::https::Client cli(server_ip_.toString(), server_port_, sni_);
  const auto resp = cli.post("/api/v1/login", request, "application/json");
  if (resp.code == 200) {
    try {
      const auto msg = resp.json();
      if (msg.contains("access_token")) {
        token_ = msg["access_token"];
        SPDLOG_INFO("Login successful");
        return true;
      } else {
        SPDLOG_ERROR(
            "Error: Access token not found in the response. Check your "
            "conection");
      }
    } catch (const nlohmann::json::parse_error& e) {
      SPDLOG_ERROR("Error parsing JSON response: {} ", e.what());
    }
  } else {
    SPDLOG_ERROR(
        "Error: Request failed code: {} msg: {}", resp.code, resp.errmsg);
  }
  return false;
}

std::pair<pcpp::IPv4Address, pcpp::IPv6Address> Client::GetDns() noexcept {
  SPDLOG_INFO("DNS. Connect to {}:{}", server_ip_.toString(), server_port_);

  fptn::common::https::Client cli(server_ip_.toString(), server_port_, sni_);
  const auto resp = cli.get("/api/v1/dns");
  if (resp.code == 200) {
    try {
      const auto msg = resp.json();
      if (msg.contains("dns")) {
        const std::string dns_ipv4 = msg["dns"];
        const std::string dns_ipv6 =
            (msg.contains("dns_ipv6") ? msg["dns_ipv6"]
                                      : FPTN_SERVER_DEFAULT_ADDRESS_IP6);
        return {pcpp::IPv4Address(dns_ipv4), pcpp::IPv6Address(dns_ipv6)};
      } else {
        SPDLOG_ERROR(
            "Error: dns not found in the response. Check your connection");
      }
    } catch (const nlohmann::json::parse_error& e) {
      SPDLOG_ERROR("Error parsing JSON response: {}", e.what());
    }
  } else {
    SPDLOG_ERROR(
        "Error: Request failed code: {} msg: {}", resp.code, resp.errmsg);
  }
  return {pcpp::IPv4Address("0.0.0.0"), pcpp::IPv6Address("")};
}

void Client::SetNewIPPacketCallback(
    const NewIPPacketCallback& callback) noexcept {
  new_ip_pkt_callback_ = callback;
}

bool Client::Send(fptn::common::network::IPPacketPtr packet) noexcept {
  try {
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

void Client::Run() noexcept {
  while (running_) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      ws_ = std::make_shared<Websocket>(server_ip_, server_port_,
          tun_interface_address_ipv4_, tun_interface_address_ipv6_,
          new_ip_pkt_callback_, sni_, token_);
    }
    ws_->Run();

    if (running_) {
      std::this_thread::sleep_for(std::chrono::seconds(3));
      SPDLOG_ERROR("Connection closed");
    }
  }
}

bool Client::Start() noexcept {
  running_ = true;
  th_ = std::thread(&Client::Run, this);
  return th_.joinable();
}

bool Client::Stop() noexcept {
  if (running_ && th_.joinable()) {
    running_ = false;
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      ws_->Stop();
    }
    th_.join();
    return true;
  }
  return false;
}

bool Client::IsStarted() noexcept {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return ws_ && ws_->IsStarted();
}
