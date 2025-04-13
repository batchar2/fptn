/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "user/user_manager.h"

#include <memory>
#include <string>
#include <utility>

#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

using fptn::user::UserManager;

UserManager::UserManager(const std::string& userfile,
    bool use_remote_server,
    std::string remote_server_ip,
    int remote_server_port)
    : use_remote_server_(use_remote_server),
      remote_server_ip_(std::move(remote_server_ip)),
      remote_server_port_(remote_server_port) {
  if (use_remote_server_) {
    // remote user list
    http_client_ = std::make_unique<fptn::common::https::Client>(
        remote_server_ip_, remote_server_port);
  } else {
    // local user list
    common_manager_ =
        std::make_unique<fptn::common::user::CommonUserManager>(userfile);
  }
}

bool UserManager::Login(const std::string& username,
    const std::string& password,
    int& bandwidthBit) const {
  bandwidthBit = 0;  // reset
  if (use_remote_server_) {
    SPDLOG_INFO(
        "Login request to {}:{}", remote_server_ip_, remote_server_port_);

    const std::string request = fmt::format(
        R"({{ "username": "{}", "password": "{}" }})", username, password);
    const auto resp =
        http_client_->post("/api/v1/login", request, "application/json");

    if (resp.code == 200) {
      try {
        const auto msg = resp.json();
        if (msg.contains("access_token") && msg.contains("bandwidth_bit")) {
          bandwidthBit = msg["bandwidth_bit"].get<int>();
          return true;
        }
        SPDLOG_INFO(
            "User manager error: Access token not found in the response. "
            "Check your connection");
      } catch (const nlohmann::json::parse_error& e) {
        SPDLOG_INFO("User manager: Error parsing JSON response: {}\n{}",
            e.what(), resp.body);
      }
    } else {
      SPDLOG_INFO(
          "User manager: request failed or response is null. Code: {} Msg: {}",
          resp.code, resp.errmsg);
    }
  } else if (common_manager_->authenticate(username, password)) {
    bandwidthBit = common_manager_->getUserBandwidthBit(username);
    return true;
  }
  return false;
}
