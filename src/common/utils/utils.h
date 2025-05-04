/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <ctime>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>

#include "common/network/ip_packet.h"

namespace fptn::common::utils {
inline std::string GenerateRandomString(int length) {
  const std::string characters =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  std::mt19937 gen {std::random_device {}()};
  std::uniform_int_distribution<std::size_t> dist(0, characters.size() - 1);

  std::string result;
  for (int i = 0; i < length; i++) {
    result += characters[dist(gen)];
  }
  return result;
}

inline std::string RemoveSubstring(
    std::string input, const std::vector<std::string>& strs) {
  for (const auto& substr : strs) {
    boost::algorithm::erase_all(input, substr);
  }
  return input;
}
}  // namespace fptn::common::utils
