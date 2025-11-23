/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-client/utils/speed_estimator/speed_estimator.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <future>
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
  std::ranges::shuffle(shuffled_servers, generator);
  const std::size_t half_size =
      std::max<std::size_t>(1, shuffled_servers.size() / 2);
  std::vector<ServerInfo> selected_servers(
      shuffled_servers.begin(), shuffled_servers.begin() + half_size);

  // Create promises and futures for all requests
  std::vector<std::promise<std::uint64_t>> promises(selected_servers.size());
  std::vector<std::future<std::uint64_t>> futures;
  futures.reserve(selected_servers.size());

  for (auto& promise : promises) {
    // cppcheck-suppress useStlAlgorithm
    futures.push_back(promise.get_future());
  }

  // Launch all requests
  for (std::size_t i = 0; i < selected_servers.size(); ++i) {
    // NOLINTNEXTLINE(bugprone-exception-escape)
    std::thread([&promise = promises[i], server = selected_servers[i], sni,
                    obfuscator]() {
      try {
        const auto cloned_obfuscator =
            (obfuscator != nullptr ? obfuscator->Clone() : nullptr);
        const auto time_ms = GetDownloadTimeMs(server, sni, kTimeoutSeconds,
            server.md5_fingerprint, cloned_obfuscator);
        promise.set_value(time_ms);
      } catch (...) {  // NOLINT
        // Set max timeout in case of exception
        promise.set_value(kMaxTimeout);
      }
    }).detach();
  }

  // Wait for all futures with timeout
  std::vector<std::uint64_t> times;
  times.reserve(futures.size());

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(kTimeoutSeconds + 2);

  for (auto& future : futures) {
    if (future.wait_until(deadline) == std::future_status::ready) {
      times.push_back(future.get());
    } else {
      // Timeout for this future
      times.push_back(kMaxTimeout);
    }
  }

  // Find fastest server
  const auto min_it = std::ranges::min_element(times);
  if (min_it == times.end() || *min_it == kMaxTimeout) {
    throw std::runtime_error("All servers unavailable!");
  }

  return selected_servers[std::distance(times.begin(), min_it)];
}

}  // namespace fptn::utils::speed_estimator
