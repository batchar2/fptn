#pragma once

#include <memory>

#include <common/https/client.h>
#include <common/user/common_user_manager.h>


namespace fptn::user {

    /**
     * @class Manager
     * @brief Handles user authentication and bandwidth retrieval for both local and remote servers.
     */
    class UserManager
    {
    public:
        /**
         * @brief Constructs a Manager object.
         *
         * @param userfile Path to the local user file for authentication.
         * @param useRemoteServer Flag indicating whether to use remote server authentication.
         * @param remoteServerIP IP address of the remote authentication server.
         * @param remoteServerPort Port number of the remote authentication server.
         */
        explicit UserManager(
            const std::string& userfile,
            bool useRemoteServer,
            const std::string& remoteServerIP,
            int remoteServerPort
        );

        /**
         * @brief Authenticates the user and retrieves the bandwidth limit.
         *
         * If the remote server is enabled, the credentials will be checked against the remote server.
         * Otherwise, local authentication will be used.
         *
         * @param username The username of the user.
         * @param password The password of the user.
         * @param bandwidthBit The bandwidth limit in bits for the user. Set upon successful login.
         *
         * @return `true` if the login is successful, `false` otherwise.
         */
        bool login(const std::string &username, const std::string &password, int& bandwidthBit) const noexcept;
    private:
        /// Indicates whether to use remote server authentication.
        const bool useRemoteServer_;

        /// IP address of the remote authentication server.
        const std::string remoteServerIP_;

        /// Port number of the remote authentication server.
        const int remoteServerPort_;

        /// HTTP client for sending requests to the remote authentication server.
        fptn::common::https::ClientPtr httpClient_;

        /// Local user manager for handling authentication using a local user file.
        fptn::common::user::CommonUserManagerPtr commonManager_;
    };

    using UserManagerSPtr = std::shared_ptr<UserManager>;
}