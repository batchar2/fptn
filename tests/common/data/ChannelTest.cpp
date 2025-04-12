/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <memory>
#include <utility>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/data/channel.h"
#include "common/network/ip_packet.h"

TEST(ChannelTest, PushAndWaitForPacket) {
  fptn::common::data::Channel channel(10);
  auto packet = std::make_unique<fptn::common::network::IPPacket>(
      "packet-data", 1, pcpp::LINKTYPE_IPV4);
  channel.push(std::move(packet));

  EXPECT_NE(channel.waitForPacket(std::chrono::milliseconds(100)), nullptr);
}

TEST(ChannelTest, WaitForPacketTimeout) {
  fptn::common::data::Channel channel(10);

  EXPECT_EQ(channel.waitForPacket(std::chrono::milliseconds(100)), nullptr);
}
