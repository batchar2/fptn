#include <string>
#include <vector>
#include <future>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <common/utils/utils.h>
#include <common/https/client.h>
#include <common/utils/base64.h>

#include "config_file.h"

using namespace fptn::config;


constexpr std::uint64_t MAX_TIMEOUT = static_cast<std::uint64_t>(-1);


ConfigFile::ConfigFile(std::string sni)
    : sni_(std::move(sni)), version_(0)
{
}

ConfigFile::ConfigFile(std::string token, std::string sni)
    : token_(std::move(token)), sni_(std::move(sni)), version_(0)
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
        const std::string decodedToken = fptn::common::utils::base64::decode(cleanToken);
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
        throw std::runtime_error(std::string("JSON parsing error: ") + e.what());
    }
    return false;
}

ConfigFile::Server ConfigFile::findFastestServer() const
{
    const int timeout = 5;
    std::vector<std::future<std::uint64_t>> futures;

    for (const auto& server : servers_) {
        futures.push_back(std::async(std::launch::async, [this, server, timeout]() {
            (void)timeout;
            return getDownloadTimeMs(server, timeout);
        }));
    }

    std::vector<std::uint64_t> times(servers_.size());
    for (std::size_t i = 0; i < futures.size(); ++i) {
        auto& future = futures[i];
        const auto status = future.wait_for(std::chrono::seconds(timeout));
        if (status == std::future_status::ready) {
            times[i] = future.get();
        } else {
            times[i] = MAX_TIMEOUT;
        }

        if (times[i] != MAX_TIMEOUT) {
            SPDLOG_INFO("Server reachable: {} at {}:{} - Download time: {}ms",
                         servers_[i].name, servers_[i].host, servers_[i].port, times[i]);
        } else {
            SPDLOG_WARN("Server unreachable: {} at {}:{}",
                         servers_[i].name, servers_[i].host, servers_[i].port);
        }
    }
    const auto minTimeIt = std::min_element(times.begin(), times.end());
    if (minTimeIt == times.end() || *minTimeIt == MAX_TIMEOUT) {
        throw std::runtime_error("All servers unavailable!");
    }
    const std::size_t fastestServerIndex = std::distance(times.begin(), minTimeIt);

    // wait futures in detached stream
    std::thread([futures = std::move(futures)]() mutable {
        (void)futures;
    }).detach();

    return servers_[fastestServerIndex];
}

std::uint64_t ConfigFile::getDownloadTimeMs(const Server& server, const int timeout) const noexcept
{
    fptn::common::https::Client cli(server.host, server.port, sni_);

    const auto start = std::chrono::high_resolution_clock::now(); // start

    const auto resp = cli.get("/api/v1/test/file.bin", timeout);
    if (resp.code == 200) {
        const auto end = std::chrono::high_resolution_clock::now();
        return  std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    } else {
        SPDLOG_ERROR("Server responded with an error: {} {}, {} ({}:{})",
            std::to_string(resp.code), resp.errmsg, server.name, server.host, server.port);
    }
    return MAX_TIMEOUT;
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
