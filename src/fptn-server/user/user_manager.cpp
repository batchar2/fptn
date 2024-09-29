#include <fmt/format.h>
#include <glog/logging.h>
#include <nlohmann/json.hpp>

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
        httpClient_ = std::make_unique<httplib::SSLClient>(remoteServerIP, remoteServerPort);
        httpClient_->enable_server_certificate_verification(false); // NEED TO FIX
        httpClient_->set_connection_timeout(5, 0); // 5 seconds
        httpClient_->set_read_timeout(5, 0);  // 5 seconds
        httpClient_->set_write_timeout(5, 0); // 5 seconds
    } else {
        // local user list
        commonManager_ = std::make_unique<fptn::common::user::CommonUserManager>(userfile);
    }
}

bool UserManager::login(const std::string &username, const std::string &password, int& bandwidthBit) const noexcept
{
    bandwidthBit = 0; // reset
    if (useRemoteServer_) {
        LOG(INFO) << "Login request to " << remoteServerIP_ << ":" << remoteServerPort_;
        std::string request = fmt::format(R"({{ "username": "{}", "password": "{}" }})",username, password);
        if (auto res = httpClient_->Post("/api/v1/login", request, "application/json")) {
            if (res->status == httplib::StatusCode::OK_200) {
                try {
                    auto response = nlohmann::json::parse(res->body);
                    if (response.contains("access_token") && response.contains("bandwidth_bit")) {
                        bandwidthBit = response["bandwidth_bit"].get<int>();
                        return true;
                    }
                    LOG(ERROR) << "User manager error: Access token not found in the response. Check your connection";
                } catch (const nlohmann::json::parse_error& e) {
                    LOG(ERROR) << "User manager: Error parsing JSON response: " << e.what() << std::endl << res->body;
                }
            } else {
                LOG(ERROR) << "User manager: " << res->body;
            }
        } else {
            auto error = res.error();
            LOG(ERROR) << "User manager: request failed or response is null." << to_string(error);
        }
    } else if (commonManager_->authenticate(username, password)) {
        bandwidthBit = commonManager_->getUserBandwidthBit(username);
        return true;
    }
    return false;
}
