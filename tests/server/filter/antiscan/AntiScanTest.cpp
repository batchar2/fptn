#include <string>
#include <gtest/gtest.h>

#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IpAddress.h>

#include <common/network/ip_packet.h>

#include <filter/packets/antiscan/antiscan.h>


class MockIPPacket : public fptn::common::network::IPPacket
{
public:
    MockIPPacket(const pcpp::IPv4Address &addr) : fptn::common::network::IPPacket()
    {
        ipv4Layer_.setDstIPv4Address(addr);
    }

    virtual pcpp::IPv4Layer* ipLayer() noexcept override
    {
        return &ipv4Layer_;
    }
private:
    pcpp::IPv4Layer ipv4Layer_;
};


TEST(AntiScanTest, BlockScan) {
    const pcpp::IPv4Address net("192.168.1.0");
    const int mask = 24;

    fptn::filter::packets::AntiScanFilter antiScanFilter(net, mask);

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPPacket>(pcpp::IPv4Address("192.168.1.5"))),
        nullptr
    ) << "Packet in the network should be blocked";

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPPacket>(pcpp::IPv4Address("192.168.1.1"))),
        nullptr
    ) << "Packet in the network should be blocked";

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPPacket>(pcpp::IPv4Address("192.168.1.255"))),
        nullptr
    ) << "Packet in the network should be blocked";
    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPPacket>(pcpp::IPv4Address("255.255.255.255"))),
        nullptr
    );
}


TEST(AntiScanTest, AllowNonScanPacket) {
    const pcpp::IPv4Address net("192.168.1.0");
    const int mask = 24;

    fptn::filter::packets::AntiScanFilter antiScanFilter(net, mask);
    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPPacket>(pcpp::IPv4Address("192.168.2.1"))),
        nullptr
    );
    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPPacket>(pcpp::IPv4Address("8.8.8.8"))),
        nullptr
    );
    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPPacket>(pcpp::IPv4Address("192.168.0.1"))),
        nullptr
    );
    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPPacket>(pcpp::IPv4Address("192.168.0.255"))),
        nullptr
    );
}
