#include <fmt/core.h>
#include <gtest/gtest.h>

#include <common/network/ip_generator.h>


TEST(IPGeneratorTest, InitialAddress)
{
    fptn::common::network::IPAddressGenerator generator(
            pcpp::IPv4Address("192.168.1.0"),
            24);
    EXPECT_EQ(generator.numAvailableAddresses(), 254);
    const auto address1 = generator.getNextAddress();
    EXPECT_EQ(address1.toString(), "192.168.1.1");

    const auto address2 = generator.getNextAddress();
    EXPECT_EQ(address2.toString(), "192.168.1.2");

    const auto address3 = generator.getNextAddress();
    EXPECT_EQ(address3.toString(), "192.168.1.3");
}


TEST(IPGeneratorTest, NumAvaliableAddresses)
{
    fptn::common::network::IPAddressGenerator generator(
            pcpp::IPv4Address("192.168.0.0"),
            24);
    EXPECT_EQ(generator.numAvailableAddresses(), 254);

    for (int i = 1; i <= 254; i++) {
        const auto address = generator.getNextAddress();
        EXPECT_EQ(address.toString(), fmt::format("192.168.0.{}", i));
    }

    { // the repeat test
        const auto address = generator.getNextAddress();
        EXPECT_EQ(address.toString(), "192.168.0.1");
    }
}


TEST(IPGeneratorTest, SmallDifficultNetsMask)
{
    fptn::common::network::IPAddressGenerator generator(
            pcpp::IPv4Address("192.168.0.0"),
            28);
    EXPECT_EQ(generator.numAvailableAddresses(), 14);
    for (int i = 1; i <= 14; i++) {
        const auto address = generator.getNextAddress();
        EXPECT_EQ(address.toString(), fmt::format("192.168.0.{}", i));
    }
}


TEST(IPGeneratorTest, BigDifficultNetsMask)
{
    fptn::common::network::IPAddressGenerator generator(
            pcpp::IPv4Address("192.168.0.0"),
            16);
    EXPECT_EQ(generator.numAvailableAddresses(), 65534);

    std::uint32_t counter = 0;
    for (int i = 0; i <= 255; i++) {
        for (int j = 0; j <= 255; j++) {
            if ((i == 0 && j == 0) || (i == 255 && j == 255)) {
                continue; // network address
            }
            const auto address = generator.getNextAddress();
            EXPECT_EQ(address.toString(), fmt::format("192.168.{}.{}", i, j));
            counter += 1;
        }
    }
    EXPECT_EQ(counter, 65534);
}
