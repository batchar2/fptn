/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/utils/speed_estimator/speed_estimator.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/api_client/api_client.h"

using fptn::protocol::https::ApiClient;
using fptn::utils::speed_estimator::ServerInfo;

constexpr std::uint64_t kMaxTimeout = UINT64_MAX;

namespace fptn::utils::speed_estimator {

std::uint64_t GetDownloadTimeMs(const ServerInfo& server,
    const std::string& sni,
    int timeout,
    const std::string& md5_fingerprint,
    const fptn::protocol::https::obfuscator::IObfuscatorSPtr& obfuscator) {
  try {
    auto const start = std::chrono::high_resolution_clock::now();
    ApiClient cli(server.host, server.port, sni, md5_fingerprint, obfuscator);
    auto const resp = cli.Get("/api/v1/test/file.bin", timeout);
    if (resp.code == 200) {
      auto const end = std::chrono::high_resolution_clock::now();
      const std::uint64_t ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
              .count();
      return ms;
    }
  } catch (const std::exception& ex) {
    SPDLOG_WARN("Exception in GetDownloadTimeMs: {}", ex.what());
  } catch (...) {
    SPDLOG_WARN("Unknown exception in GetDownloadTimeMs");
  }
  return kMaxTimeout;
}

ServerInfo FindFastestServer(const std::string& sni,
    const std::vector<ServerInfo>& servers,
    const fptn::protocol::https::obfuscator::IObfuscatorSPtr& obfuscator) {
  constexpr int kTimeoutSeconds = 30;

  // randomly select half of the servers
  std::vector<ServerInfo> shuffled_servers = servers;
  std::random_device rd;
  std::mt19937 generator(rd());
  std::shuffle(shuffled_servers.begin(), shuffled_servers.end(), generator);
  const std::size_t half_size =
      std::max<std::size_t>(1, shuffled_servers.size() / 2);
  std::vector<ServerInfo> selected_servers(
      shuffled_servers.begin(), shuffled_servers.begin() + half_size);

  // Simple shared state
  struct SharedState {
    std::mutex mutex;
    std::condition_variable cv;
    std::uint64_t min_time = kMaxTimeout;
    std::size_t fastest_server_index = 0;
    bool found = false;
  };

  auto state = std::make_shared<SharedState>();

  // Launch all requests
  for (std::size_t i = 0; i < selected_servers.size(); ++i) {
    // NOLINTNEXTLINE(bugprone-exception-escape)
    std::thread([state, server = selected_servers[i], i, sni, obfuscator]() {
      try {
        auto cloned_obfuscator =
            (obfuscator != nullptr ? obfuscator->Clone() : nullptr);
        auto time = GetDownloadTimeMs(server, sni, kTimeoutSeconds,
            server.md5_fingerprint, cloned_obfuscator);

        const std::scoped_lock<std::mutex> lock(state->mutex);  // mutex
        if (!state->found && time < state->min_time) {
          state->min_time = time;
          state->fastest_server_index = i;
          if (time != kMaxTimeout) {
            state->found = true;
            state->cv.notify_one();
          }
        }
      } catch (...) {  // NOLINT
        // Ignore exceptions in background threads
      }
    }).detach();
  }

  // Wait for result with timeout
  std::unique_lock<std::mutex> lock(state->mutex);
  if (!state->cv.wait_for(lock, std::chrono::seconds(kTimeoutSeconds),
          [state]() { return state->found; })) {
    // Timeout reached
    state->found = true;  // Force exit
  }

  if (state->min_time == kMaxTimeout) {
    throw std::runtime_error("All servers unavailable!");
  }

  return selected_servers[state->fastest_server_index];
}

}  // namespace fptn::utils::speed_estimator
