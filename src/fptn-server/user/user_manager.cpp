#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include "user_manager.h"

using namespace fptn::user;


UserManager::UserManager(
    const std::string& userfile,
    bool useRemoteServer,
    const std::string& remoteServerIP,
    int remoteServerPort
)
    :
        useRemoteServer_(useRemoteServer),
        remoteServerIP_(remoteServerIP),
        remoteServerPort_(remoteServerPort)
{
    if (useRemoteServer_) {
        // remote user list
        httpClient_ = std::make_unique<fptn::common::https::Client>(remoteServerIP, remoteServerPort);
    } else {
        // local user list
        commonManager_ = std::make_unique<fptn::common::user::CommonUserManager>(userfile);
    }
}

bool UserManager::login(const std::string &username, const std::string &password, int& bandwidthBit) const noexcept
{
    bandwidthBit = 0; // reset
    if (useRemoteServer_) {
        SPDLOG_INFO("Login request to {}:{}", remoteServerIP_, remoteServerPort_);

        const std::string request = fmt::format(R"({{ "username": "{}", "password": "{}" }})",username, password);
        const auto resp = httpClient_->post("/api/v1/login", request, "application/json");

        if (resp.code == 200) {
            try {
                const auto msg = resp.json();
                if (msg.contains("access_token") && msg.contains("bandwidth_bit")) {
                    bandwidthBit = msg["bandwidth_bit"].get<int>();
                    return true;
                }
                SPDLOG_INFO("User manager error: Access token not found in the response. Check your connection");
            } catch (const nlohmann::json::parse_error& e) {
                SPDLOG_INFO("User manager: Error parsing JSON response: {}\n{}", e.what(), resp.body);
            }
        } else {
            SPDLOG_INFO("User manager: request failed or response is null. Code: {} Msg: {}", resp.code, resp.errmsg);
        }
    } else if (commonManager_->authenticate(username, password)) {
        bandwidthBit = commonManager_->getUserBandwidthBit(username);
        return true;
    }
    return false;
}
