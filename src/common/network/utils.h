/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <vector>

#include "common/system/command.h"

namespace fptn::common::network {

std::vector<std::string> GetServerIpAddresses() {
  std::vector<std::string> cmd_stdout;
  fptn::common::system::command::run(
      "ip -o addr show | awk '{print $4}' | cut -d'/' -f1", cmd_stdout);
  return cmd_stdout;
}
}  // namespace fptn::common::network
