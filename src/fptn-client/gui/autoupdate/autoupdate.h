#pragma once

#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <httplib/httplib.h>


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
        constexpr int seconds = 5;

        httplib::SSLClient client("api.github.com", 443);
        client.set_connection_timeout(seconds, 0);
        client.set_read_timeout(seconds, 0);
        client.set_write_timeout(seconds, 0);
        client.enable_server_certificate_verification(false);

        const auto url = fmt::format("/repos/{}/{}/releases/latest", FPTN_GITHUB_USERNAME, FPTN_GITHUB_REPOSITORY);
        if (auto res = client.Get(url)) {
            if (res->status == httplib::StatusCode::OK_200) {
                try {
                    auto response = nlohmann::json::parse(res->body);
                    if (response.contains("draft") && response.contains("name")) {
                        const bool draft = response["draft"];
                        const std::string versionName = response["name"];
                        if (!draft && version::compare(FPTN_VERSION, versionName) == -1) {
                            return {true, versionName};
                        }
                        return {false, versionName};
                    }
                } catch (const nlohmann::json::parse_error& e) {
                    spdlog::error("Error parsing JSON response: {}  {}", e.what(), res->body);
                }
            }
        }
        return {false, {}};
    }
}
