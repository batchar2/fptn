/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <fmt/core.h>  // NOLINT(build/include_order)

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ipv6_generator.h"

TEST(IPv6GeneratorTest, InitialAddress) {
  fptn::common::network::IPv6AddressGenerator generator(
      fptn::common::network::IPv6Address(
          "2001:0db8:0000:0000:0000:0000:0000:0000"),
      120);
  EXPECT_EQ(generator.NumAvailableAddresses(), 254);

  const auto address1 = generator.GetNextAddress();
  EXPECT_EQ(address1.ToString(), "2001:0db8:0000:0000:0000:0000:0000:0001");

  const auto address2 = generator.GetNextAddress();
  EXPECT_EQ(address2.ToString(), "2001:0db8:0000:0000:0000:0000:0000:0002");

  const auto address3 = generator.GetNextAddress();
  EXPECT_EQ(address3.ToString(), "2001:0db8:0000:0000:0000:0000:0000:0003");
}

TEST(IPv6GeneratorTest, NumAvaliableAddresses) {
  fptn::common::network::IPv6AddressGenerator generator(
      fptn::common::network::IPv6Address(
          "2001:0db8:0001:0000:0000:0000:0000:0000"),
      120);
  EXPECT_EQ(generator.NumAvailableAddresses(), 254);

  for (int i = 1; i <= 254; i++) {
    const auto address = generator.GetNextAddress();
    EXPECT_EQ(address.ToString(),
        fmt::format("2001:0db8:0001:0000:0000:0000:0000:{:04x}", i));
  }

  {  // Repeat test
    const auto address = generator.GetNextAddress();
    EXPECT_EQ(address.ToString(), "2001:0db8:0001:0000:0000:0000:0000:0001");
  }
}

TEST(IPv6GeneratorTest, SmallDifficultNetsMask) {
  fptn::common::network::IPv6AddressGenerator generator(
      fptn::common::network::IPv6Address(
          "2001:0db8:0002:0000:0000:0000:0000:0000"),
      124);
  EXPECT_EQ(generator.NumAvailableAddresses(), 14);

  for (int i = 1; i <= 14; i++) {
    const auto address = generator.GetNextAddress();
    EXPECT_EQ(address.ToString(),
        fmt::format("2001:0db8:0002:0000:0000:0000:0000:{:04x}", i));
  }
}

TEST(IPv6GeneratorTest, BigDifficultNetsMask) {
  fptn::common::network::IPv6AddressGenerator generator(
      fptn::common::network::IPv6Address(
          "2001:0db8:0003:0000:0000:0000:0000:0000"),
      112);
  EXPECT_EQ(generator.NumAvailableAddresses(), (1ULL << 16) - 2);

  std::uint32_t counter = 0;
  for (int i = 0; i <= 255; i++) {
    for (int j = 0; j <= 255; j++) {
      if ((i == 0 && j == 0) || (i == 255 && j == 255)) {
        continue;  // Skip network and broadcast addresses
      }
      const auto address = generator.GetNextAddress();
      EXPECT_EQ(address.ToString(),
          fmt::format("2001:0db8:0003:0000:0000:0000:{:02x}{:02x}:{:02x}{:02x}",
              0, 0, i, j));
      counter += 1;
    }
  }
  EXPECT_EQ(counter, (1ULL << 16) - 2);
}
