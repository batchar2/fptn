/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <fmt/core.h>  // NOLINT(build/include_order)

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ipv6_generator.h"

TEST(IPv6GeneratorTest, InitialAddress) {
  fptn::common::network::IPv6AddressGenerator generator(
      pcpp::IPv6Address("2001:db8::"), 120);
  EXPECT_EQ(generator.NumAvailableAddresses(), 254);

  const auto address1 = generator.GetNextAddress();
  EXPECT_EQ(address1.toString(), "2001:db8::1");

  const auto address2 = generator.GetNextAddress();
  EXPECT_EQ(address2.toString(), "2001:db8::2");

  const auto address3 = generator.GetNextAddress();
  EXPECT_EQ(address3.toString(), "2001:db8::3");
}

TEST(IPv6GeneratorTest, NumAvaliableAddresses) {
  fptn::common::network::IPv6AddressGenerator generator(
      pcpp::IPv6Address("2001:db8:1::"), 120);
  EXPECT_EQ(generator.NumAvailableAddresses(), 254);

  for (int i = 1; i <= 254; i++) {
    const auto address = generator.GetNextAddress();
    EXPECT_EQ(address.toString(), fmt::format("2001:db8:1::{:x}", i));
  }

  {  // Repeat test
    const auto address = generator.GetNextAddress();
    EXPECT_EQ(address.toString(), "2001:db8:1::1");
  }
}

TEST(IPv6GeneratorTest, SmallDifficultNetsMask) {
  fptn::common::network::IPv6AddressGenerator generator(
      pcpp::IPv6Address("2001:db8:2::"), 124);
  EXPECT_EQ(generator.NumAvailableAddresses(), 14);

  for (int i = 1; i <= 14; i++) {
    const auto address = generator.GetNextAddress();
    EXPECT_EQ(address.toString(), fmt::format("2001:db8:2::{:x}", i));
  }
}

TEST(IPv6GeneratorTest, BigDifficultNetsMask) {
  fptn::common::network::IPv6AddressGenerator generator(
      pcpp::IPv6Address("2001:db8:3::"), 112);
  EXPECT_EQ(generator.NumAvailableAddresses(), (1ULL << 16) - 2);

  std::uint32_t counter = 0;
  for (int i = 0; i <= 255; i++) {
    for (int j = 0; j <= 255; j++) {
      if ((i == 0 && j == 0) || (i == 255 && j == 255)) {
        continue;  // Skip network and broadcast addresses
      }
      const auto address = generator.GetNextAddress();
      EXPECT_EQ(
          address.toString(), fmt::format("2001:db8:3::{:x}", (i << 8) + j));
      counter += 1;
    }
  }
  EXPECT_EQ(counter, (1ULL << 16) - 2);
}
