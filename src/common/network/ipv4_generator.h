/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cinttypes>
#include <memory>
#include <string>

#if _WIN32
#pragma warning(disable : 4996)
#endif

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include <pcapplusplus/EthLayer.h>   // NOLINT(build/include_order)
#include <pcapplusplus/IPv4Layer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/Packet.h>     // NOLINT(build/include_order)

#if _WIN32
#pragma warning(default : 4996)
#endif

namespace fptn::common::network {

class IPv4AddressGenerator {
 public:
  IPv4AddressGenerator(
      const pcpp::IPv4Address& netAddress, std::uint32_t subnetMask)
      : ip_(boost::asio::ip::address_v4::from_string(netAddress.toString())),
        netAddr_(
            boost::asio::ip::address_v4::from_string(netAddress.toString())) {
    // cppcheck-suppress useInitializationList
    netmask_ = boost::asio::ip::address_v4(
        (subnetMask == 0)
            ? 0
            : (~static_cast<std::uint32_t>(0) << (32 - subnetMask)));

    uint32_t ip_num = ip_.to_uint();
    uint32_t netmask_num = netmask_.to_uint();

    uint32_t network_address = ip_num & netmask_num;
    broadcast_ =
        boost::asio::ip::address_v4(network_address | ~netmask_.to_uint());

    numAvailableAddresses_ = (1U << (32 - subnetMask)) - 2;
  }

  std::uint32_t numAvailableAddresses() const noexcept {
    return numAvailableAddresses_;
  }

  pcpp::IPv4Address getNextAddress() noexcept {
    const std::unique_lock<std::mutex> lock(mutex_);

    const std::uint32_t newIP = ip_.to_uint() + 1;
    if (newIP < broadcast_.to_uint()) {
      ip_ = boost::asio::ip::address_v4(newIP);
    } else {
      ip_ = boost::asio::ip::address_v4(netAddr_.to_uint() + 1);
    }
    return pcpp::IPv4Address(ip_.to_string());
  }

 private:
  mutable std::mutex mutex_;
  boost::asio::ip::address_v4 ip_;
  boost::asio::ip::address_v4 netAddr_;

  boost::asio::ip::address_v4 netmask_;
  boost::asio::ip::address_v4 broadcast_;

  std::uint32_t numAvailableAddresses_;
};
using IPv4AddressGeneratorSPtr = std::shared_ptr<IPv4AddressGenerator>;
}  // namespace fptn::common::network
