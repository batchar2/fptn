/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/time/time_provider.h"

#include <string>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::time {

TimeProvider::TimeProvider(const std::string& ntp_host, uint16_t ntp_port)
    : ntp_client_(ntp_host, ntp_port), offset_seconds_(0) {
  for (int i = 0; i < 5; i++) {  // make some attempts
    if (SyncWithNtp()) {
      break;
    }
  }
}

std::int32_t TimeProvider::OffsetSeconds() const { return offset_seconds_; }

std::uint32_t TimeProvider::NowTimestamp() const {
  const auto timestamp = static_cast<std::int64_t>(std::time(nullptr));
  return static_cast<std::uint32_t>(timestamp + offset_seconds_);
}

std::uint64_t TimeProvider::SyncWithNtp() {
  const auto epoch_server_ms = ntp_client_.request_time();

  if (epoch_server_ms) {
    const auto server_timestamp =
        static_cast<std::uint64_t>(epoch_server_ms / 1000);
    const auto client_timestamp = static_cast<std::int64_t>(std::time(nullptr));
    offset_seconds_ =
        static_cast<std::int32_t>(server_timestamp - client_timestamp);
    SPDLOG_INFO(
        "Successfully synchronized with NTP server. "
        "Server timestamp: {}, "
        "local timestamp: {}, "
        "calculated offset: {} seconds",
        server_timestamp, client_timestamp, offset_seconds_);
  } else {
    SPDLOG_ERROR(
        "Failed to get time from NTP server. "
        "Using local system time without synchronization");
  }
  return epoch_server_ms;
}

}  // namespace fptn::time
