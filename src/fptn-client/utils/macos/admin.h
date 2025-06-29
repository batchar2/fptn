#pragma once

/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <string>
#include <iostream>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#ifdef __APPLE__

#include <Security/Authorization.h>      // NOLINT(build/include_order)
#include <Security/AuthorizationTags.h>  // NOLINT(build/include_order)
#include <libgen.h>                      // NOLINT(build/include_order)
#include <libproc.h>                     // NOLINT(build/include_order)
#include <mach-o/dyld.h>                 // NOLINT(build/include_order)
#include <sys/sysctl.h>                  // NOLINT(build/include_order)

namespace fptn::utils::macos {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

bool RestartApplicationWithAdminRights() {
  // Already running as root? No need to restart.
  if (geteuid() == 0) {
    return true;
  }

  // Initialize AuthorizationRef
  AuthorizationRef auth_ref = nullptr;
  OSStatus status = AuthorizationCreate(nullptr, kAuthorizationEmptyEnvironment,
      kAuthorizationFlagDefaults, &auth_ref);

  if (status != errAuthorizationSuccess) {
    std::cerr << "Failed to create authorization reference.\n";
    return false;
  }

  // Request admin rights
  const char* kAdminRights[] = {kAuthorizationRightExecute,
      "system.preferences", "system.preferences.network",
      "system.services.systemconfiguration.network"};

  AuthorizationItem rights[4] = {};
  for (size_t i = 0; i < 4; ++i) {
    rights[i] = {kAdminRights[i], 0, nullptr, 0};
  }

  AuthorizationRights rights_set = {4, rights};
  AuthorizationFlags flags = kAuthorizationFlagDefaults |
                             kAuthorizationFlagInteractionAllowed |
                             kAuthorizationFlagExtendRights;

  status =
      AuthorizationCopyRights(auth_ref, &rights_set, nullptr, flags, nullptr);
  if (status != errAuthorizationSuccess) {
    AuthorizationFree(auth_ref, kAuthorizationFlagDefaults);
    std::cerr << "Failed to obtain admin rights.\n";
    return false;
  }

  // Get current executable path
  char executablePath[PATH_MAX] = {};
  uint32_t pathSize = sizeof(executablePath);
  if (_NSGetExecutablePath(executablePath, &pathSize) != 0) {
    AuthorizationFree(auth_ref, kAuthorizationFlagDefaults);
    std::cerr << "Failed to get executable path.\n";
    return false;
  }

  // Restart with privileges
  char* args[] = {const_cast<char*>(executablePath), nullptr};
  status = AuthorizationExecuteWithPrivileges(
      auth_ref, executablePath, kAuthorizationFlagDefaults, args, nullptr);

  AuthorizationFree(auth_ref, kAuthorizationFlagDefaults);

  if (status != errAuthorizationSuccess) {
    std::cerr << "Failed to restart with admin rights.\n";
    return false;
  }
  // Exit the current instance (only the elevated one will continue)
  exit(EXIT_SUCCESS);
  return true;
}
#pragma clang diagnostic pop

}  // namespace fptn::utils::macos

#endif
