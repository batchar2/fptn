#pragma once

#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <common/https/client.h>

#include <iostream>


namespace fptn::gui::autoupdate
{
    namespace version
    {
        inline std::vector<int> parse(const std::string &version)
        {
            std::vector<int> parsed;
            std::stringstream ss(version);
            std::string segment;
            while (std::getline(ss, segment, '.')) {
                parsed.push_back(std::stoi(segment));
            }
            return parsed;
        }

        inline int compare(const std::string &version1, const std::string &version2)
        {
            std::vector<int> v1 = parse(version1);
            std::vector<int> v2 = parse(version2);

            const std::size_t maxLength = std::max(v1.size(), v2.size());
            v1.resize(maxLength, 0);
            v2.resize(maxLength, 0);
            for (size_t i = 0; i < maxLength; ++i) {
                if (v1[i] < v2[i]) return -1;  // version1 is less than version2
                if (v1[i] > v2[i]) return 1;   // version1 is greater than version2
            }
            return 0;
        }
    }

    inline std::pair<bool, std::string> check()
    {
        fptn::common::https::Client cli("api.github.com", 443);

        const auto url = fmt::format("/repos/{}/{}/releases/latest", FPTN_GITHUB_USERNAME, FPTN_GITHUB_REPOSITORY);
        const auto resp = cli.get(url);

        if (resp.code == 200) {
            try {
                const auto msg = resp.json();
                if (msg.contains("draft") && msg.contains("name")) {
                    const bool draft = msg["draft"];
                    const std::string versionName = msg["name"];
                    if (!draft && version::compare(FPTN_VERSION, versionName) == -1) {
                        return {true, versionName};
                    }
                    return {false, versionName};
                }
            } catch (const nlohmann::json::parse_error& e) {
                spdlog::error("autoupdate:check Error parsing JSON response: {}  {}", e.what(), resp.body);
            }
        }
        return {false, {}};
    }
}
