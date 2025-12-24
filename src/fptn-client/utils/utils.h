/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>

#include <re2/re2.h>  // NOLINT(build/include_order)

#include "common/utils/utils.h"

namespace fptn::utils {

inline std::string DomainToRegex(const std::string& pattern) {
  const std::string domain_prefix = "domain:";
  const std::string trimmed = fptn::common::utils::Trim(pattern);

  if (!trimmed.starts_with(domain_prefix)) {
    return {};
  }

  const std::string domain = trimmed.substr(domain_prefix.length());
  if (domain.empty()) {
    return {};
  }

  std::string escaped;
  escaped.reserve(domain.length() * 2);
  for (const char c : fptn::common::utils::ToLowerCase(domain)) {
    if (c == '.') {
      escaped += "\\.";
    } else {
      escaped += c;
    }
  }
  // return R"(\.)" + escaped + R"($)";
  // return R"((?:^|\.))" + escaped + R"((?:\.|$)?)";
  return R"((?:^|\.))" + escaped + R"($)";
}
}  // namespace fptn::utils
