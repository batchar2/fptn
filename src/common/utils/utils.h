/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <algorithm>
#include <ctime>
#include <random>
#include <ranges>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/locale.hpp>

namespace fptn::common::utils {
inline std::string GenerateRandomString(const int length) {
  const std::string characters =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  std::mt19937 gen{std::random_device{}()};
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

inline std::string Trim(const std::string& str) {
  auto is_space = [](const unsigned char c) { return std::isspace(c); };

  const auto start = std::ranges::find_if_not(str, is_space);
  const auto end =
      std::ranges::find_if_not(str | std::views::reverse, is_space).base();

  return (start < end) ? std::string(start, end) : std::string();
}

inline std::vector<std::string> SplitCommaSeparated(const std::string& input) {
  std::vector<std::string> result;
  std::stringstream ss(input);
  std::string item;

  while (std::getline(ss, item, ',')) {
    const std::string trimmed = Trim(item);
    if (!trimmed.empty()) {
      result.push_back(trimmed);
    }
  }
  return result;
}

inline std::string ToLowerCase(const std::string& str) {
  try {
    boost::locale::generator gen;
    std::locale loc = gen("");
    return boost::locale::to_lower(str, loc);
  } catch (...) {
    return str;
  }
  return str;
}

inline std::string FilterDigitsOnly(const std::string& input) {
  std::string result;
  result.reserve(input.size());

  std::ranges::copy_if(input, std::back_inserter(result),
      [](const unsigned char c) { return std::isdigit(c); });

  return result;
}

}  // namespace fptn::common::utils
