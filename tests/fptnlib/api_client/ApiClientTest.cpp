/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <nlohmann/json.hpp>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/api_client/api_client.h"

/*
TEST(ApiClientTest, GitHubReleasesConnection) {
    fptn::protocol::https::ApiClient client(
        "api.github.com",
        443,
        "api.github.com",
        nullptr,
        false
    );

    auto response = client.Get("/repos/batchar2/fptn/releases/latest", 30);

    EXPECT_EQ(response.code, 200);
    EXPECT_FALSE(response.body.empty());

    auto release_info = response.Json();
    EXPECT_TRUE(release_info.contains("tag_name"));
    EXPECT_TRUE(release_info.contains("name"));
    EXPECT_TRUE(release_info.contains("html_url"));
}
*/

TEST(ApiClientTest, GitHubHandshakeTest) {
  fptn::protocol::https::ApiClient client(
      "api.github.com", 443, "api.github.com", nullptr, false);

  bool handshake_success = client.TestHandshake(10);
  EXPECT_TRUE(handshake_success);
}

/*
TEST(ApiClientTest, GitHubResponseStructure) {
    fptn::protocol::https::ApiClient client(
        "api.github.com",
        443,
        "api.github.com",
        nullptr,
        false
    );

    auto response = client.Get("/repos/batchar2/fptn/releases/latest", 30);

    ASSERT_EQ(response.code, 200);

    auto release_info = response.Json();
    EXPECT_TRUE(release_info.contains("id"));
    EXPECT_TRUE(release_info.contains("tag_name"));
    EXPECT_TRUE(release_info.contains("assets"));

    if (release_info.contains("assets") && release_info["assets"].is_array()) {
        auto assets = release_info["assets"];
        if (!assets.empty()) {
            //auto asset = assets[0];
            //EXPECT_TRUE(asset.contains("name"));
            //EXPECT_TRUE(asset.contains("browser_download_url"));
        }
    }
}
*/
