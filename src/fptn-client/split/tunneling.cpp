/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "split/tunneling.h"

#include <algorithm>
#include <memory>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace {

std::string Trim(const std::string& str) {
  const auto start = str.find_first_not_of(" \t\n\r");
  if (start == std::string::npos) {
    return {};
  }
  const auto end = str.find_last_not_of(" \t\n\r");
  return str.substr(start, end - start + 1);
}

std::optional<std::regex> RuleToRegex(const std::string& rule) {
  if (rule.empty()) {
    return std::nullopt;
  }

  std::string regex_str;
  for (const char c : Trim(rule)) {
    if (c == '*') {
      regex_str += ".*";
    } else if (c == '.') {
      regex_str += "\\.";
    } else {
      regex_str += c;
    }
  }
  if (!regex_str.empty() && rule[0] != '*') {
    regex_str = "^" + regex_str + "$";
  }
  return std::regex(regex_str);
  // return std::nullopt;
}

}  // namespace

namespace fptn::split {
Tunneling::Tunneling(
    const std::vector<std::string>& rules, RouteManagerPtr route_manager)
    : route_manager_(std::move(route_manager)) {
  for (const auto& rule : rules) {
    auto regex_opt = RuleToRegex(rule);
    if (regex_opt) {
      rules_.push_back(std::move(*regex_opt));
    } else {
      SPDLOG_WARN("Failed to parse rule: {}", rule);
    }
  }
}

fptn::common::network::IPPacketPtr Tunneling::HandlePacket(
    fptn::common::network::IPPacketPtr packet) const {
  if (packet->IsDns()) {
    const auto domain_opt = packet->GetDnsDomain();
    if (domain_opt.has_value() && MatchDomain(domain_opt.value())) {
      SPDLOG_INFO("Domain '{}' matched rule", domain_opt.value());
      // set route in split route manager
      const auto ipv4_addresses = packet->GetDnsIPv4Addresses();
      const auto ipv6_addresses = packet->GetDnsIPv6Addresses();

      route_manager_->AddRoutesIPv4(ipv4_addresses);
      route_manager_->AddRoutesIPv6(ipv6_addresses);
    }
  }
  return packet;
}

bool Tunneling::MatchDomain(const std::string& domain) const {
  if (domain.empty()) {
    return false;
  }

  const bool result = std::ranges::any_of(rules_, [&domain](const auto& rule) {
    try {
      if (std::regex_match(domain, rule)) {
        return true;
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN("Regex error for domain '{}': {}", domain, e.what());
    }
    return false;
  });
  return result;
}

}  // namespace fptn::split
