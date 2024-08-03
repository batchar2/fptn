#include <thread>
#include <chrono>

#include <gtest/gtest.h>

#include <common/data/channel.h>



// class MockIPPacket : public IPPacket {
//     // Mock implementation
// };


TEST(ChannelTest, PushAndWaitForPacket)
{
    fptn::common::data::Channel channel(10);
    // auto pkt = std::make_shared<MockIPPacket>();

    // channel.push(pkt);

    // EXPECT_EQ(channel.waitForPacket(std::chrono::milliseconds(100)), pkt);
}


// TEST(ChannelTest, WaitForPacketTimeout)
// {
//     Channel channel(10);

//     EXPECT_EQ(channel.waitForPacket(std::chrono::milliseconds(100)), nullptr);
// }


// TEST(ChannelTest, MultiplePushAndWaitForPacket)
// {
//     Channel channel(10);
//     auto pkt1 = std::make_shared<MockIPPacket>();
//     auto pkt2 = std::make_shared<MockIPPacket>();

//     channel.push(pkt1);
//     channel.push(pkt2);

//     EXPECT_EQ(channel.waitForPacket(std::chrono::milliseconds(100)), pkt1);
//     EXPECT_EQ(channel.waitForPacket(std::chrono::milliseconds(100)), pkt2);
// }