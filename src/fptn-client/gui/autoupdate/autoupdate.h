/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <algorithm>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/https/client.h"

#if _WIN32
#ifdef max
#pragma push_macro("max")
#undef max
#define MAX_MACRO_WAS_DEFINED
#endif
#endif

namespace fptn::gui::autoupdate {
namespace version {
inline std::vector<int> ParseVersion(const std::string& version) {
  std::vector<int> parsed;
  std::stringstream ss(version);
  std::string segment;
  while (std::getline(ss, segment, '.')) {
    parsed.push_back(std::stoi(segment));
  }
  return parsed;
}

inline int compare(const std::string& version1, const std::string& version2) {
  std::vector<int> v1 = ParseVersion(version1);
  std::vector<int> v2 = ParseVersion(version2);

  const std::size_t max_length = (std::max)(v1.size(), v2.size());
  v1.resize(max_length, 0);
  v2.resize(max_length, 0);
  for (size_t i = 0; i < max_length; ++i) {
    if (v1[i] < v2[i]) return -1;  // version1 is less than version2
    if (v1[i] > v2[i]) return 1;   // version1 is greater than version2
  }
  return 0;
}
}  // namespace version

inline std::pair<bool, std::string> Check() {
  fptn::common::https::Client cli("api.github.com", 443);

  const auto url = fmt::format("/repos/{}/{}/releases/latest",
      FPTN_GITHUB_USERNAME, FPTN_GITHUB_REPOSITORY);
  const auto resp = cli.Get(url);

  if (resp.code == 200) {
    try {
      const auto msg = resp.Json();
      if (msg.contains("draft") && msg.contains("name")) {
        const bool draft = msg["draft"];
        const std::string version_name = msg["name"];
        if (!draft && version::compare(FPTN_VERSION, version_name) == -1) {
          return {true, version_name};
        }
        return {false, version_name};
      }
    } catch (const nlohmann::json::parse_error& e) {
      SPDLOG_ERROR("autoupdate:check Error parsing JSON response: {}  {}",
          e.what(), resp.body);
    }
  }
  return {false, {}};
}

#if _WIN32
#ifdef MAX_MACRO_WAS_DEFINED
#pragma pop_macro("max")
#undef MAX_MACRO_WAS_DEFINED
#endif
#endif

}  // namespace fptn::gui::autoupdate
