/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>

#include "common/user/common_user_manager.h"

#include "fptn-client-protocol-lib/https/https_client.h"

namespace fptn::user {

/**
 * @class Manager
 * @brief Handles user authentication and bandwidth retrieval for both local and
 * remote servers.
 */
class UserManager {
 public:
  /**
   * @brief Constructs a Manager object.
   *
   * @param userfile Path to the local user file for authentication.
   * @param useRemoteServer Flag indicating whether to use remote server
   * authentication.
   * @param remoteServerIP IP address of the remote authentication server.
   * @param remoteServerPort Port number of the remote authentication server.
   */
  explicit UserManager(const std::string& userfile,
      bool use_remote_server,
      std::string remote_server_ip,
      int remote_server_port);

  /**
   * @brief Authenticates the user and retrieves the bandwidth limit.
   *
   * If the remote server is enabled, the credentials will be checked against
   * the remote server. Otherwise, local authentication will be used.
   *
   * @param username The username of the user.
   * @param password The password of the user.
   * @param bandwidthBit The bandwidth limit in bits for the user. Set upon
   * successful login.
   *
   * @return `true` if the login is successful, `false` otherwise.
   */
  bool Login(const std::string& username,
      const std::string& password,
      int& bandwidthBit) const;

 private:
  /// Indicates whether to use remote server authentication.
  const bool use_remote_server_;

  /// IP address of the remote authentication server.
  const std::string remote_server_ip_;

  /// Port number of the remote authentication server.
  const int remote_server_port_;

  /// HTTP client for sending requests to the remote authentication server.
  fptn::client::protocol::lib::https::HttpsClientPtr http_client_;

  /// Local user manager for handling authentication using a local user file.
  fptn::common::user::CommonUserManagerPtr common_manager_;
};

using UserManagerSPtr = std::shared_ptr<UserManager>;
}  // namespace fptn::user
