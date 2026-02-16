/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include "common/client_id.h"
#include "common/network/ip_address.h"

namespace fptn::nat {
struct ConnectParams {
  ClientID client_id = MAX_CLIENT_ID;
  struct Request {
    std::string url;

    std::string jwt_auth_token;
    std::string session_id;

    std::uint64_t connection_weight = 1;

    fptn::common::network::IPv4Address client_ipv4;
    fptn::common::network::IPv4Address client_tun_vpn_ipv4;
    fptn::common::network::IPv6Address client_tun_vpn_ipv6;
  } request;

  struct User {
    std::string username;
    std::size_t bandwidth_bites_seconds = 0;
  } user;

  struct Timings {
    std::chrono::system_clock::time_point expire_after;
    std::chrono::system_clock::time_point silence_mode_until;

    [[nodiscard]] bool HasExpiration() const noexcept {
      return expire_after > std::chrono::system_clock::time_point{};
    }

    [[nodiscard]] bool IsSilenceModeActive() const noexcept {
      const auto now = std::chrono::system_clock::now();
      return silence_mode_until > now;
    }

    void SetExpireAfter(const std::uint64_t ts) noexcept {
      if (ts != 0) {
        expire_after = std::chrono::system_clock::from_time_t(
            static_cast<std::time_t>(ts));
      } else {
        expire_after = std::chrono::system_clock::time_point{};
      }
    }

    void SetSilenceModeUntil(const std::uint64_t ts) noexcept {
      if (ts != 0) {
        silence_mode_until = std::chrono::system_clock::from_time_t(
            static_cast<std::time_t>(ts));
      } else {
        silence_mode_until = std::chrono::system_clock::time_point{};
      }
    }

  } timings;

  bool Validate() const {
    return client_id != MAX_CLIENT_ID && !request.client_ipv4.IsEmpty() &&
           !request.client_tun_vpn_ipv4.IsEmpty() &&
           !request.client_tun_vpn_ipv6.IsEmpty() &&
           !request.jwt_auth_token.empty() && !request.session_id.empty();
  }
};
}  // namespace fptn::nat
