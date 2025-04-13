/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "config/config_file.h"

#include <algorithm>
#include <future>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/https/client.h"
#include "common/utils/base64.h"
#include "common/utils/utils.h"

using fptn::config::ConfigFile;

constexpr std::uint64_t kMaxTimeout = UINT64_MAX;

ConfigFile::ConfigFile(std::string sni) : sni_(std::move(sni)), version_(0) {}

ConfigFile::ConfigFile(std::string token, std::string sni)
    : token_(std::move(token)), sni_(std::move(sni)), version_(0) {}

bool ConfigFile::AddServer(ConfigFile::Server const& s) {
  servers_.push_back(s);
  return true;
}

bool ConfigFile::Parse() {
  try {
    const std::string clean_token = fptn::common::utils::RemoveSubstring(
        token_, {"fptn://", "fptn:", " ", "\n", "\r", "\t"});
    const std::string decoded_token =
        fptn::common::utils::base64::decode(clean_token);
    auto const config = nlohmann::json::parse(decoded_token);

    version_ = config.at("version").get<int>();
    service_name_ = config.at("service_name").get<std::string>();
    username_ = config.at("username").get<std::string>();
    password_ = config.at("password").get<std::string>();
    for (auto const& server : config.at("servers")) {
      Server s(server.at("name").get<std::string>(),
          server.at("host").get<std::string>(), server.at("port").get<int>());
      servers_.push_back(s);
    }
    if (!servers_.empty()) {
      return true;
    }
    throw std::runtime_error("Server list is empty!");
  } catch (nlohmann::json::exception const& e) {
    throw std::runtime_error(std::string("JSON parsing error: ") + e.what());
  }
  return false;
}

ConfigFile::Server ConfigFile::FindFastestServer() const {
  constexpr int kTimeout = 5;
  std::vector<std::future<std::uint64_t>> futures;

  futures.reserve(servers_.size());
  // NOLINTNEXTLINE(modernize-use-ranges)
  std::transform(servers_.begin(), servers_.end(), std::back_inserter(futures),
      // NOLINTNEXTLINE(bugprone-exception-escape)
      [this](const auto& server) {
        try {
          // NOLINTNEXTLINE(modernize-use-ranges)
          return std::async(std::launch::async,
              // NOLINTNEXTLINE(bugprone-exception-escape)
              [this, server]() { return GetDownloadTimeMs(server, kTimeout); });
        } catch (const std::exception& ex) {
          SPDLOG_ERROR("Exception in GetDownloadTimeMs: {}", ex.what());
          return std::async(std::launch::deferred, [] { return kMaxTimeout; });
        } catch (...) {
          SPDLOG_ERROR("Unknown error occurred in GetDownloadTimeMs");
          return std::async(std::launch::deferred, [] { return kMaxTimeout; });
        }
      });

  std::vector<std::uint64_t> times(servers_.size());
  for (std::size_t i = 0; i < futures.size(); ++i) {
    auto& future = futures[i];
    auto const status = future.wait_for(std::chrono::seconds(kTimeout));
    if (status == std::future_status::ready) {
      times[i] = future.get();
    } else {
      times[i] = kMaxTimeout;
    }

    if (times[i] != kMaxTimeout) {
      SPDLOG_INFO("Server reachable: {} at {}:{} - Download time: {}ms",
          servers_[i].name, servers_[i].host, servers_[i].port, times[i]);
    } else {
      SPDLOG_WARN("Server unreachable: {} at {}:{}", servers_[i].name,
          servers_[i].host, servers_[i].port);
    }
  }
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

  return servers_[fastest_server_index];
}

std::uint64_t ConfigFile::GetDownloadTimeMs(
    Server const& server, int const timeout) const noexcept {
  fptn::common::https::Client cli(server.host, server.port, sni_);

  auto const start = std::chrono::high_resolution_clock::now();  // start

  auto const resp = cli.Get("/api/v1/test/file.bin", timeout);
  if (resp.code != 200) {
    SPDLOG_ERROR("Server responded with an error: {} {}, {} ({}:{})",
        std::to_string(resp.code), resp.errmsg, server.name, server.host,
        server.port);
  } else {
    auto const end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
        .count();
  }
  return kMaxTimeout;
}

int ConfigFile::GetVersion() const noexcept { return version_; }

const std::string& ConfigFile::GetServiceName() const noexcept {
  return service_name_;
}

const std::string& ConfigFile::GetUsername() const noexcept {
  return username_;
}

const std::string& ConfigFile::GetPassword() const noexcept {
  return password_;
}

const std::vector<ConfigFile::Server>& ConfigFile::GetServers() const noexcept {
  return servers_;
}
