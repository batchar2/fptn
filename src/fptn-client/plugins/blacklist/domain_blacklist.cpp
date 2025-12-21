/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "plugins/blacklist/domain_blacklist.h"

#include <memory>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

#include "common/utils/utils.h"

#include "utils/utils.h"

namespace fptn::plugin {

DomainBlacklist::DomainBlacklist(const std::vector<std::string>& rules) {
  RE2::Options re_options;
  re_options.set_case_sensitive(false);
  re_options.set_log_errors(false);

  for (const auto& rule : rules) {
    const std::string regex_pattern = fptn::utils::DomainToRegex(rule);
    if (!regex_pattern.empty()) {
      auto re = std::make_unique<RE2>(regex_pattern, re_options);
      if (re->ok()) {
        SPDLOG_INFO("Added blacklist rule: '{}' -> '{}'", rule, regex_pattern);
        rules_.push_back(std::move(re));
      } else {
        SPDLOG_WARN("Invalid regex pattern: {}, item={}", re->error(), rule);
      }
    } else {
      SPDLOG_WARN("Wrong pattern {}", rule);
    }
  }
}

fptn::common::network::IPPacketPtr DomainBlacklist::HandlePacket(
    fptn::common::network::IPPacketPtr packet) {
  if (packet->IsDns()) {
    const auto domain_opt = packet->GetDnsDomain();
    if (domain_opt.has_value()) {
      const std::string& domain = domain_opt.value();

      if (std::ranges::any_of(rules_, [&domain](const auto& re) {
            return RE2::PartialMatch(domain, *re);
          })) {
        SPDLOG_INFO("Domain {} is blacklisted", domain);
        return nullptr;
      }
    }
  }
  return packet;
}

}  // namespace fptn::plugin
