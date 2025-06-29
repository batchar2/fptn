#pragma once

/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <string>
#include <vector>

#include "common/system/command.h"

namespace fptn::utils::windows {

inline bool HasVpnConflicts(std::string& found_adapters) {
  found_adapters = "";

  // Command to list network interfaces that might indicate VPN conflicts
  constexpr char command[] =
      "powershell.exe -Command \"Get-NetAdapter | Where-Object { "
      "$_.InterfaceDescription -match 'VPN|TAP|WireGuard|OpenVPN|Tunnel' -and "
      "$_.Status -eq 'Up' } | Select-Object -ExpandProperty Name\"";


  std::vector<std::string> adapter_names;
  fptn::common::system::command::run(command, adapter_names);

  // Check if any VPN-related interfaces were found
  for (const auto& name : adapter_names) {
    if (!name.empty()) {
      if (found_adapters.empty()) {
        found_adapters = name;
      } else {
        found_adapters += ", " + name;
      }
    }
  }
  return !found_adapters.empty();
}

}  // namespace fptn::utils::windows
