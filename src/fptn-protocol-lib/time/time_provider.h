/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace fptn::time {

using NtpServers = std::vector<std::pair<std::string, std::uint16_t>>;

class TimeProvider final {
 public:
  static TimeProvider* Instance() {
    static TimeProvider provider;
    return &provider;
  }

  std::string Rfc7231Date();
  std::int32_t OffsetSeconds() const;
  std::uint32_t NowTimestamp();
  bool SyncWithNtp();

 protected:
  explicit TimeProvider(NtpServers servers = {
                            {"ru.pool.ntp.org", 123},
                            {"ntp.ix.ru", 123},
                            {"europe.pool.ntp.org", 123},
                            {"cn.pool.ntp.org", 123}
                        });
  bool Refresh();

 private:
  const std::chrono::minutes kSyncInterval_{5};

  mutable std::mutex mutex_;
  const NtpServers servers_;

  std::atomic<std::int32_t> offset_seconds_;
  std::atomic<std::chrono::steady_clock::time_point> last_sync_time_;
};

}  // namespace fptn::time
