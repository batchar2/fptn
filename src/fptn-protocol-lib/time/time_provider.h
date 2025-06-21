/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>

#include <ntp_client.hpp>

namespace fptn::time {

class TimeProvider final {
 public:
  static TimeProvider* Instance() {
    static TimeProvider provider;
    return &provider;
  }

  std::int32_t OffsetSeconds() const;
  std::uint32_t NowTimestamp() const;

 protected:
  explicit TimeProvider(
      const std::string& ntp_host = "pool.ntp.org", int ntp_port = 123);

  std::uint64_t SyncWithNtp();

 private:
  NTPClient ntp_client_;
  std::int32_t offset_seconds_;
};

}  // namespace fptn::time
