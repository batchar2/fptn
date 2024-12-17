#include <string>
#include <gtest/gtest.h>

#include <statistic/metrics.h>


TEST(MetricsTest, UpdateTraffic) {
    fptn::statistic::Metrics metrics;
    metrics.updateStatistics(1, "user1", 1024, 2048);

    const std::string metrics_data = metrics.collect();
    EXPECT_NE(metrics_data.find("fptn_user_incoming_traffic_bytes{session_id=\"1\",username=\"user1\"} 1024"), std::string::npos);
    EXPECT_NE(metrics_data.find("fptn_user_outgoing_traffic_bytes{session_id=\"1\",username=\"user1\"} 2048"), std::string::npos);
}
