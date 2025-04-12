/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <memory>
#include <string>

#include <pcapplusplus/IPv4Layer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/IPv6Layer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/IpAddress.h>  // NOLINT(build/include_order)

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"

#include "fptn-server/filter/filters/antiscan/antiscan.h"

class MockIPv4Packet : public fptn::common::network::IPPacket {
 public:
  explicit MockIPv4Packet(const pcpp::IPv4Address& addr)
      : fptn::common::network::IPPacket() {
    ipv4Layer_.setDstIPv4Address(addr);
  }

  bool IsIPv4() const noexcept override { return true; }

  bool IsIPv6() const noexcept override { return false; }

  pcpp::IPv4Layer* IPv4Layer() noexcept override { return &ipv4Layer_; }

 private:
  pcpp::IPv4Layer ipv4Layer_;
};

class MockIPv6Packet : public fptn::common::network::IPPacket {
 public:
  explicit MockIPv6Packet(const pcpp::IPv6Address& addr)
      : fptn::common::network::IPPacket() {
    ipv6Layer_.setDstIPv6Address(addr);
  }

  bool IsIPv4() const noexcept override { return false; }

  bool IsIPv6() const noexcept override { return true; }

  pcpp::IPv6Layer* IPv6Layer() noexcept override { return &ipv6Layer_; }

 private:
  pcpp::IPv6Layer ipv6Layer_;
};

/* IPv4 */
TEST(AntiScanTest, BlockScan) {
  /* IPv4 */
  const pcpp::IPv4Address server_ipv4("192.168.1.1");
  const pcpp::IPv4Address net_ipv4("192.168.1.0");
  const int mask_ipv4 = 24;
  /* IPv6 */
  const pcpp::IPv6Address server_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0001");
  const pcpp::IPv6Address net_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:0000");
  const int mask_ipv6 = 126;

  fptn::filter::AntiScan anti_scan_filter(
      /* IPv4 */
      server_ipv4, net_ipv4, mask_ipv4,
      /* IPv6 */
      server_ipv6, net_ipv6, mask_ipv6);

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(net_ipv4)),
      nullptr)
      << "Packet in the network should be blocked";

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                pcpp::IPv4Address("192.168.1.5"))),
      nullptr)
      << "Packet in the network should be blocked";

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                pcpp::IPv4Address("192.168.1.255"))),
      nullptr)
      << "Packet in the network should be blocked";

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                pcpp::IPv4Address("255.255.255.255"))),
      nullptr);
}

TEST(AntiScanTest, AllowNonScanPacket) {
  /* IPv4 */
  const pcpp::IPv4Address server_ipv4("192.168.1.1");
  const pcpp::IPv4Address net_ipv4("192.168.1.0");
  const int mask_ipv4 = 24;
  /* IPv6 */
  const pcpp::IPv6Address server_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0001");
  const pcpp::IPv6Address net_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:0000");
  const int mask_ipv6 = 126;

  fptn::filter::AntiScan anti_scan_filter(
      /* IPv4 */
      server_ipv4, net_ipv4, mask_ipv4,
      /* IPv6 */
      server_ipv6, net_ipv6, mask_ipv6);

  EXPECT_NE(
      anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(server_ipv4)),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                pcpp::IPv4Address("192.168.2.1"))),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(
                std::make_unique<MockIPv4Packet>(pcpp::IPv4Address("8.8.8.8"))),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                pcpp::IPv4Address("192.168.0.1"))),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv4Packet>(
                pcpp::IPv4Address("192.168.0.255"))),
      nullptr);
}

/* IPv6 */
TEST(AntiScanTest, BlockScanIPv6) {
  /* IPv4 */
  const pcpp::IPv4Address server_ipv4("192.168.1.1");
  const pcpp::IPv4Address net_ipv4("192.168.1.0");
  const int mask_ipv4 = 24;
  /* IPv6 */
  const pcpp::IPv6Address server_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0001");
  const pcpp::IPv6Address net_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:0000");
  const int mask_ipv6 = 120;

  fptn::filter::AntiScan anti_scan_filter(
      /* IPv4 */
      server_ipv4, net_ipv4, mask_ipv4,
      /* IPv6 */
      server_ipv6, net_ipv6, mask_ipv6);

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(net_ipv6)),
      nullptr)
      << "IPv6 packet in the network should be blocked";

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(
                pcpp::IPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:0002"))),
      nullptr);

  EXPECT_EQ(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(
                pcpp::IPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:00A0"))),
      nullptr);
}

TEST(AntiScanTest, AllowNonScanPacketIPv6) {
  /* IPv4 */
  const pcpp::IPv4Address server_ipv4("192.168.1.1");
  const pcpp::IPv4Address net_ipv4("192.168.1.0");
  const int mask_ipv4 = 24;
  /* IPv6 */
  const pcpp::IPv6Address server_ipv6(
      "2001:0db8:85a3:0000:0000:8a2e:0370:0001");
  const pcpp::IPv6Address net_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:0000");
  const int mask_ipv6 = 126;

  fptn::filter::AntiScan anti_scan_filter(
      /* IPv4 */
      server_ipv4, net_ipv4, mask_ipv4,
      /* IPv6 */
      server_ipv6, net_ipv6, mask_ipv6);

  EXPECT_NE(
      anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(server_ipv6)),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(
                pcpp::IPv6Address("2001:0db8:85a3:0000:0000:8a2e:0371:1000"))),
      nullptr);

  EXPECT_NE(anti_scan_filter.apply(std::make_unique<MockIPv6Packet>(
                pcpp::IPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:FFFF"))),
      nullptr);
}
