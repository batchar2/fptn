/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <string>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "fptn-server/statistic/metrics.h"

TEST(MetricsTest, UpdateTraffic) {
  fptn::statistic::Metrics metrics;
  metrics.UpdateStatistics(1, "user1", 1024, 2048);

  const std::string metrics_data = metrics.Collect();
  EXPECT_NE(metrics_data.find("fptn_user_incoming_traffic_bytes{session_id="
                              "\"1\",username=\"user1\"} 1024"),
      std::string::npos);
  EXPECT_NE(metrics_data.find("fptn_user_outgoing_traffic_bytes{session_id="
                              "\"1\",username=\"user1\"} 2048"),
      std::string::npos);
}
