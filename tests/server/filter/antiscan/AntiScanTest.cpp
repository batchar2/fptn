#include <string>
#include <gtest/gtest.h>

#include <pcapplusplus/IpAddress.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>

#include <common/network/ip_packet.h>
#include <filter/packets/antiscan/antiscan.h>


class MockIPv4Packet : public fptn::common::network::IPPacket
{
public:
    MockIPv4Packet(const pcpp::IPv4Address &addr) : fptn::common::network::IPPacket()
    {
        ipv4Layer_.setDstIPv4Address(addr);
    }

    virtual const bool isIPv4() const noexcept override
    {
        return true;
    }

    virtual const bool isIPv6() const noexcept override
    {
        return false;
    }

    virtual pcpp::IPv4Layer* ipv4Layer() noexcept override
    {
        return &ipv4Layer_;
    }
private:
    pcpp::IPv4Layer ipv4Layer_;
};


class MockIPv6Packet : public fptn::common::network::IPPacket
{
public:
    MockIPv6Packet(const pcpp::IPv6Address &addr) : fptn::common::network::IPPacket()
    {
        ipv6Layer_.setDstIPv6Address(addr);
    }

    virtual const bool isIPv4() const noexcept override
    {
        return false;
    }

    virtual const bool isIPv6() const noexcept override
    {
        return true;
    }

    virtual pcpp::IPv6Layer* ipv6Layer() noexcept override
    {
        return &ipv6Layer_;
    }
private:
    pcpp::IPv6Layer ipv6Layer_;
};


/* IPv4 */
TEST(AntiScanTest, BlockScan) {
    /* IPv4 */
    const pcpp::IPv4Address serverIPv4("192.168.1.1");
    const pcpp::IPv4Address netIPv4("192.168.1.0");
    const int maskIPv4 = 24;
    /* IPv6 */
    const pcpp::IPv6Address serverIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:0001");
    const pcpp::IPv6Address netIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:0000");
    const int maskIPv6 = 126;

    fptn::filter::packets::AntiScanFilter antiScanFilter(
        /* IPv4 */
        serverIPv4, netIPv4, maskIPv4,
        /* IPv6 */
        serverIPv6, netIPv6, maskIPv6
    );

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPv4Packet>(netIPv4)),
        nullptr
    ) << "Packet in the network should be blocked";

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPv4Packet>(pcpp::IPv4Address("192.168.1.5"))),
        nullptr
    ) << "Packet in the network should be blocked";

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPv4Packet>(pcpp::IPv4Address("192.168.1.255"))),
        nullptr
    ) << "Packet in the network should be blocked";

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPv4Packet>(pcpp::IPv4Address("255.255.255.255"))),
        nullptr
    );
}


TEST(AntiScanTest, AllowNonScanPacket) {
    /* IPv4 */
    const pcpp::IPv4Address serverIPv4("192.168.1.1");
    const pcpp::IPv4Address netIPv4("192.168.1.0");
    const int maskIPv4 = 24;
    /* IPv6 */
    const pcpp::IPv6Address serverIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:0001");
    const pcpp::IPv6Address netIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:0000");
    const int maskIPv6 = 126;

    fptn::filter::packets::AntiScanFilter antiScanFilter(
        /* IPv4 */
        serverIPv4, netIPv4, maskIPv4,
        /* IPv6 */
        serverIPv6, netIPv6, maskIPv6
    );

    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPv4Packet>(serverIPv4)),
        nullptr
    );

    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPv4Packet>(pcpp::IPv4Address("192.168.2.1"))),
        nullptr
    );

    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPv4Packet>(pcpp::IPv4Address("8.8.8.8"))),
        nullptr
    );

    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPv4Packet>(pcpp::IPv4Address("192.168.0.1"))),
        nullptr
    );

    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPv4Packet>(pcpp::IPv4Address("192.168.0.255"))),
        nullptr
    );
}


/* IPv6 */
TEST(AntiScanTest, BlockScanIPv6) {
    /* IPv4 */
    const pcpp::IPv4Address serverIPv4("192.168.1.1");
    const pcpp::IPv4Address netIPv4("192.168.1.0");
    const int maskIPv4 = 24;
    /* IPv6 */
    const pcpp::IPv6Address serverIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:0001");
    const pcpp::IPv6Address netIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:0000");
    const int maskIPv6 = 120;

    fptn::filter::packets::AntiScanFilter antiScanFilter(
        /* IPv4 */
        serverIPv4, netIPv4, maskIPv4,
        /* IPv6 */
        serverIPv6, netIPv6, maskIPv6
    );

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPv6Packet>(netIPv6)),
        nullptr
    ) << "IPv6 packet in the network should be blocked";

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPv6Packet>(pcpp::IPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:0002"))),
        nullptr
    );

    EXPECT_EQ(
        antiScanFilter.apply(std::make_unique<MockIPv6Packet>(pcpp::IPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:00A0"))),
        nullptr
    );
}

TEST(AntiScanTest, AllowNonScanPacketIPv6) {
    /* IPv4 */
    const pcpp::IPv4Address serverIPv4("192.168.1.1");
    const pcpp::IPv4Address netIPv4("192.168.1.0");
    const int maskIPv4 = 24;
    /* IPv6 */
    const pcpp::IPv6Address serverIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:0001");
    const pcpp::IPv6Address netIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:0000");
    const int maskIPv6 = 126;

    fptn::filter::packets::AntiScanFilter antiScanFilter(
        /* IPv4 */
        serverIPv4, netIPv4, maskIPv4,
        /* IPv6 */
        serverIPv6, netIPv6, maskIPv6
    );

    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPv6Packet>(serverIPv6)),
        nullptr
    );

    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPv6Packet>(pcpp::IPv6Address("2001:0db8:85a3:0000:0000:8a2e:0371:1000"))),
        nullptr
    );

    EXPECT_NE(
        antiScanFilter.apply(std::make_unique<MockIPv6Packet>(pcpp::IPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:FFFF"))),
        nullptr
    );
}