/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/server/speed_estimator.h"

#include <algorithm>
#include <future>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "fptn-protocol-lib/https/https_client.h"

using fptn::protocol::https::HttpsClient;
using fptn::protocol::server::ServerInfo;

constexpr std::uint64_t kMaxTimeout = UINT64_MAX;

namespace fptn::protocol::server {

// NOLINTNEXTLINE(misc-use-internal-linkage)
std::uint64_t GetDownloadTimeMs(const ServerInfo& server,
    const std::string& sni,
    int timeout,
    const std::string& md5_fingerprint) {
  auto const start = std::chrono::high_resolution_clock::now();  // start

  HttpsClient cli(server.host, server.port, sni, md5_fingerprint);
  auto const resp = cli.Get("/api/v1/test/file.bin", timeout);
  if (resp.code == 200) {
    auto const end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
        .count();
  }
  return kMaxTimeout;
}

ServerInfo FindFastestServer(
    const std::string& sni, const std::vector<ServerInfo>& servers) {
  constexpr int kTimeoutSeconds = 30;
  std::vector<std::future<std::uint64_t>> futures;

  futures.reserve(servers.size());
  // NOLINTNEXTLINE(modernize-use-ranges)
  std::transform(servers.begin(), servers.end(), std::back_inserter(futures),
      // NOLINTNEXTLINE(bugprone-exception-escape)
      [kTimeoutSeconds, sni](const auto& server) {
        (void)kTimeoutSeconds;  // fix Windows build
        try {
          // NOLINTNEXTLINE(modernize-use-ranges)
          return std::async(std::launch::async,
              // NOLINTNEXTLINE(bugprone-exception-escape)
              [server, sni, kTimeoutSeconds]() {
                (void)kTimeoutSeconds;  // fix Windows build
                return GetDownloadTimeMs(
                    server, sni, kTimeoutSeconds, server.md5_fingerprint);
              });
        } catch (const std::exception& ex) {
          (void)ex;
          // SPDLOG_ERROR("Exception in GetDownloadTimeMs: {}", ex.what());
          return std::async(std::launch::deferred, [] { return kMaxTimeout; });
        } catch (...) {
          // SPDLOG_ERROR("Unknown error occurred in GetDownloadTimeMs");
          return std::async(std::launch::deferred, [] { return kMaxTimeout; });
        }
      });

  std::vector<std::uint64_t> times(servers.size(), kMaxTimeout);
  const auto time_begin = std::chrono::high_resolution_clock::now();
  const auto timeout_time = time_begin + std::chrono::seconds(kTimeoutSeconds);

  bool any_ready = false;
  do {
    // Check all server connections for responses
    for (std::size_t i = 0; i < futures.size(); ++i) {
      auto& future = futures[i];
      auto const status = future.wait_for(std::chrono::milliseconds(1));
      if (status == std::future_status::ready) {
        times[i] = future.get();
        any_ready = true;
      }
    }

    // Exit loop if we've exceeded maximum allowed time
    if (std::chrono::high_resolution_clock::now() > timeout_time) {
      break;
    }

    // Only sleep if no servers responded this iteration
    if (!any_ready) {
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
  } while (!any_ready);

  // NOLINTNEXTLINE(modernize-use-ranges)
  auto const min_time_it = std::min_element(times.begin(), times.end());
  if (min_time_it == times.end() || *min_time_it == kMaxTimeout) {
    throw std::runtime_error("All servers unavailable!");
  }
  const std::size_t fastest_server_index =
      std::distance(times.begin(), min_time_it);

  // wait for futures in detached stream
  std::thread([futures = std::move(futures)]() mutable {
    (void)futures;
  }).detach();

  return servers[fastest_server_index];
}
}  // namespace fptn::protocol::server
