#pragma once

#include <pcapplusplus/IPv6Layer.h>

#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>


namespace fptn::common::network::ipv6
{
    inline boost::multiprecision::uint128_t toUInt128(const boost::asio::ip::address_v6 &address)
    {
        boost::multiprecision::uint128_t result {};
        for (uint8_t b : address.to_bytes()) {
            (result <<= 8) |= b;
        }
        return result;
    }

    inline boost::multiprecision::uint128_t toUInt128(const pcpp::IPv6Address& address)
    {
        return toUInt128(
            boost::asio::ip::make_address_v6(address.toString())
        );
    }

    inline std::string toString(const boost::multiprecision::uint128_t& val)
    {
        const std::uint64_t high = static_cast<uint64_t>(val >> 64); // High 64 bits
        const std::uint64_t low = static_cast<uint64_t>(val & 0xFFFFFFFFFFFFFFFF); // Low 64 bits
        std::stringstream ss;
        ss << std::hex << std::setw(4) << std::setfill('0') << (high >> 48) << ':'
           << std::setw(4) << (high >> 32 & 0xFFFF) << ':'
           << std::setw(4) << (high >> 16 & 0xFFFF) << ':'
           << std::setw(4) << (high & 0xFFFF) << ':'
           << std::setw(4) << (low >> 48) << ':'
           << std::setw(4) << (low >> 32 & 0xFFFF) << ':'
           << std::setw(4) << (low >> 16 & 0xFFFF) << ':'
           << std::setw(4) << (low & 0xFFFF);
        return ss.str();
    }
}
