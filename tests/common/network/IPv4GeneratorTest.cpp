/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <fmt/core.h>  // NOLINT(build/include_order)

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ipv4_generator.h"

TEST(IPv4GeneratorTest, InitialAddress) {
  fptn::common::network::IPv4AddressGenerator generator(
      fptn::common::network::IPv4Address("192.168.1.0"), 24);
  EXPECT_EQ(generator.NumAvailableAddresses(), 254);
  const auto address1 = generator.GetNextAddress();
  EXPECT_EQ(address1.ToString(), "192.168.1.1");

  const auto address2 = generator.GetNextAddress();
  EXPECT_EQ(address2.ToString(), "192.168.1.2");

  const auto address3 = generator.GetNextAddress();
  EXPECT_EQ(address3.ToString(), "192.168.1.3");
}

TEST(IPv4GeneratorTest, NumAvaliableAddresses) {
  fptn::common::network::IPv4AddressGenerator generator(
      fptn::common::network::IPv4Address("192.168.0.0"), 24);
  EXPECT_EQ(generator.NumAvailableAddresses(), 254);

  for (int i = 1; i <= 254; i++) {
    const auto address = generator.GetNextAddress();
    EXPECT_EQ(address.ToString(), fmt::format("192.168.0.{}", i));
  }

  {  // the repeat test
    const auto address = generator.GetNextAddress();
    EXPECT_EQ(address.ToString(), "192.168.0.1");
  }
}

TEST(IPv4GeneratorTest, SmallDifficultNetsMask) {
  fptn::common::network::IPv4AddressGenerator generator(
      fptn::common::network::IPv4Address("192.168.0.0"), 28);
  EXPECT_EQ(generator.NumAvailableAddresses(), 14);
  for (int i = 1; i <= 14; i++) {
    const auto address = generator.GetNextAddress();
    EXPECT_EQ(address.ToString(), fmt::format("192.168.0.{}", i));
  }
}

TEST(IPGeneratorTest, BigDifficultNetsMask) {
  fptn::common::network::IPv4AddressGenerator generator(
      fptn::common::network::IPv4Address("192.168.0.0"), 16);
  EXPECT_EQ(generator.NumAvailableAddresses(), 65534);

  std::uint32_t counter = 0;
  for (int i = 0; i <= 255; i++) {
    for (int j = 0; j <= 255; j++) {
      if ((i == 0 && j == 0) || (i == 255 && j == 255)) {
        continue;  // network address
      }
      const auto address = generator.GetNextAddress();
      EXPECT_EQ(address.ToString(), fmt::format("192.168.{}.{}", i, j));
      counter += 1;
    }
  }
  EXPECT_EQ(counter, 65534);
}
