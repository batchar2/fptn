/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/time/time_provider.h"

#include <string>
#include <utility>

#include <ntp_client.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::time {

TimeProvider::TimeProvider(NtpServers servers)
    : servers_(std::move(servers)), offset_seconds_(0) {
  SyncWithNtp();
}

std::int32_t TimeProvider::OffsetSeconds() const {
  return offset_seconds_.load();
}

std::uint32_t TimeProvider::NowTimestamp() {
  const std::lock_guard<std::mutex> lock(mutex_);

  const auto now = std::chrono::steady_clock::now();
  if (now - last_sync_time_.load() > kSyncInterval_) {
    Refresh();
  }

  return static_cast<std::uint32_t>(
      std::time(nullptr) + offset_seconds_.load());
}

bool TimeProvider::SyncWithNtp() {
  const std::lock_guard<std::mutex> lock(mutex_);

  return Refresh();
}

bool TimeProvider::Refresh() {
  for (const auto& [server, port] : servers_) {
    try {
      NTPClient ntp_client(server, port);
      const auto epoch_server_ms = ntp_client.request_time();
      if (epoch_server_ms) {
        const auto server_timestamp =
            static_cast<std::uint64_t>(epoch_server_ms / 1000);
        const auto client_timestamp =
            static_cast<std::int64_t>(std::time(nullptr));
        offset_seconds_ =
            static_cast<std::int32_t>(server_timestamp - client_timestamp);
        last_sync_time_ = std::chrono::steady_clock::now();
        SPDLOG_INFO(
            "Successfully synchronized with NTP server '{}'. "
            "Server timestamp: {}, "
            "local timestamp: {}, "
            "calculated offset: {} seconds",
            server, server_timestamp, client_timestamp, offset_seconds_.load());
        return true;
      }
    } catch (...) {
      SPDLOG_WARN("Unknown error during NTP request to {}:{}", server, port);
    }
  }
  SPDLOG_ERROR(
      "Failed to get time from NTP server. "
      "Using local system time without synchronization");
  return false;
}

}  // namespace fptn::time
