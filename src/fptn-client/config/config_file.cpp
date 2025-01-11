#include <string>
#include <vector>
#include <future>

#include <base64.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <httplib/httplib.h>

#include <common/utils/utils.h>

#include "config_file.h"

using namespace fptn::config;


ConfigFile::ConfigFile(std::string token)
    : token_(std::move(token)), version_(0)
{
}

bool ConfigFile::addServer(const ConfigFile::Server &s)
{
    servers_.push_back(s);
    return true;
}

bool ConfigFile::parse()
{
    try {
        const std::string cleanToken = fptn::common::utils::removeSubstring(
            token_,
            {"fptn://", "fptn:", " ", "\n", "\r", "\t"}
        );
        const std::string decodedToken = base64::from_base64(cleanToken + "==");
        const auto config = nlohmann::json::parse(decodedToken);

        version_ = config.at("version").get<int>();
        serviceName_ = config.at("service_name").get<std::string>();
        username_ = config.at("username").get<std::string>();
        password_ = config.at("password").get<std::string>();
        for (const auto& server : config.at("servers")) {
            Server s;
            s.name = server.at("name").get<std::string>();
            s.host = server.at("host").get<std::string>();
            s.port = server.at("port").get<int>();
            servers_.push_back(s);
        }
        if (!servers_.empty()) {
            return true;
        }
        throw std::runtime_error("Server list is empty!");
    } catch (const nlohmann::json::exception& e) {
        throw std::runtime_error(std::string("JSON parsing error!") + e.what());
    }
    return false;
}

ConfigFile::Server ConfigFile::findFastestServer() const
{
    std::vector<std::future<std::uint64_t>> futures;
    for (const auto& server : servers_) {
        futures.push_back(std::async(std::launch::async, [this, server]() {
            return getDownloadTimeMs(server);
        }));
    }
    std::vector<std::uint64_t> times(servers_.size());
    for (size_t i = 0; i < futures.size(); ++i) {
        const std::uint64_t time = futures[i].get();
        times[i] = time;
        if (time != static_cast<std::uint64_t>(-1)) {
            spdlog::info("Server reachable: {} at {}:{} - Download time: {}ms",
                         servers_[i].name, servers_[i].host, servers_[i].port, time);
        } else {
            spdlog::warn("Server unreachable: {} at {}:{}",
                         servers_[i].name, servers_[i].host, servers_[i].port);
        }
    }
    auto minTimeIt = std::min_element(times.begin(), times.end());
    if (minTimeIt == times.end() || *minTimeIt == static_cast<std::uint64_t>(-1)) {
        throw std::runtime_error("All servers unavailable!");
    }
    std::size_t fastestServerIndex = std::distance(times.begin(), minTimeIt);
    return servers_[fastestServerIndex];
}

std::uint64_t ConfigFile::getDownloadTimeMs(const Server& server) const noexcept
{
    try {
        httplib::SSLClient cli(server.host, server.port);
        cli.enable_server_certificate_verification(false); // NEED TO FIX
        cli.set_connection_timeout(5, 0); // 5 seconds
        cli.set_read_timeout(5, 0);  // 5 seconds
        cli.set_write_timeout(5, 0); // 5 seconds

        auto start = std::chrono::high_resolution_clock::now(); // start
        if (auto res = cli.Get("/api/v1/test/file.bin")) {
            if (res->status == 200) {
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                return duration;
            }
            spdlog::error("Server responded with an error: {} {} ({}:{})",
                          std::to_string(res->status), server.name, server.host, server.port);
        } else {
            spdlog::error("Failed to connect to the server: {} ({}:{})", server.name, server.host, server.port);
        }
    } catch (const std::exception& e) {
        spdlog::error("Error while downloading from server: {}", e.what());
    }
    return static_cast<std::uint64_t>(-1);
}

int ConfigFile::getVersion() const noexcept
{
    return version_;
}

std::string ConfigFile::getServiceName() const noexcept
{
    return serviceName_;
}

std::string ConfigFile::getUsername() const noexcept
{
    return username_;
}

std::string ConfigFile::getPassword() const noexcept
{
    return password_;
}

std::vector<ConfigFile::Server> ConfigFile::getServers() const noexcept
{
    return servers_;
}
