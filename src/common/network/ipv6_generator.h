#pragma once

#include <string>
#include <memory>
#include <cinttypes>
#include <mutex>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv6Layer.h>

#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include "ipv6_utils.h"


namespace fptn::common::network
{
    class IPv6AddressGenerator
    {
    public:
        IPv6AddressGenerator(const pcpp::IPv6Address &netAddress, std::uint32_t subnetMask)
        {
            const auto netAddressBoost = boost::asio::ip::address_v6::from_string(netAddress.toString());
            netAddr_ = ipv6::toUInt128(netAddressBoost);
            maxAddr_ = netAddr_ | ((boost::multiprecision::uint128_t(1) << (128 - subnetMask)) - 1);
            currentAddr_ = netAddr_;
        }

        pcpp::IPv6Address getNextAddress() noexcept
        {
            const std::unique_lock<std::mutex> lock(mutex_);
            const auto newIP = currentAddr_ + 1;
            if (newIP < maxAddr_) {
                currentAddr_ = newIP;
            } else {
                currentAddr_ = netAddr_ + 1;
            }
            return ipv6::toString(currentAddr_);
        }
        const boost::multiprecision::uint128_t numAvailableAddresses() const
        {
            return maxAddr_ - netAddr_ - 1;
        }
    private:
    private:
        mutable std::mutex mutex_;

        boost::multiprecision::uint128_t netAddr_;
        boost::multiprecision::uint128_t maxAddr_;
        boost::multiprecision::uint128_t currentAddr_;
    };

    using IPv6AddressGeneratorSPtr = std::shared_ptr<IPv6AddressGenerator>;
}

