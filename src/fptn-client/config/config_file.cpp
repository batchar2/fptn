/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "config/config_file.h"

#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/utils/base64.h"
#include "common/utils/utils.h"

using fptn::config::ConfigFile;
using fptn::utils::speed_estimator::ServerInfo;

ConfigFile::ConfigFile(std::string sni,
    fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator)
    : sni_(std::move(sni)), version_(0), obfuscator_(std::move(obfuscator)) {}

ConfigFile::ConfigFile(std::string token,
    std::string sni,
    fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator)
    : token_(std::move(token)),
      sni_(std::move(sni)),
      version_(0),
      obfuscator_(std::move(obfuscator)) {}

bool ConfigFile::AddServer(const ServerInfo& s) {
  servers_.push_back(s);
  return true;
}

bool ConfigFile::Parse() {
  try {
    const std::string sanitized_token = fptn::common::utils::RemoveSubstring(
        token_, {"fptn://", "fptn:", " ", "\n", "\r", "\t", "="});

    const std::string decoded_token =
        fptn::common::utils::base64::decode(sanitized_token);
    auto const config = nlohmann::json::parse(decoded_token);

    version_ = config.at("version").get<int>();
    service_name_ = config.at("service_name").get<std::string>();
    username_ = config.at("username").get<std::string>();
    password_ = config.at("password").get<std::string>();
    for (auto const& server : config.at("servers")) {
      ServerInfo s(server.at("name").get<std::string>(),
          server.at("host").get<std::string>(), server.at("port").get<int>(),
          server.at("md5_fingerprint").get<std::string>());
      servers_.push_back(s);
    }
    if (!servers_.empty()) {
      return true;
    }
    throw std::runtime_error("Server list is empty!");
  } catch (nlohmann::json::exception const& e) {
    throw std::runtime_error(std::string("JSON parsing error: ") + e.what() +
                             ". Try to update your token");
  }
  return false;
}

ServerInfo ConfigFile::FindFastestServer() const {
  return fptn::utils::speed_estimator::FindFastestServer(
      sni_, servers_, obfuscator_);
}

std::uint64_t ConfigFile::GetDownloadTimeMs(const ServerInfo& server,
    const std::string& sni,
    int timeout,
    const std::string& md5_fingerprint) {
  return fptn::utils::speed_estimator::GetDownloadTimeMs(
      server, sni, timeout, md5_fingerprint, obfuscator_);
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

const std::vector<ServerInfo>& ConfigFile::GetServers() const noexcept {
  return servers_;
}
