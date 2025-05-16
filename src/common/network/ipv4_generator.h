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
      const pcpp::IPv4Address& netAddress, std::uint32_t subnet_mask)
      : ip_(boost::asio::ip::make_address_v4(netAddress.toString())),
        net_addr_(boost::asio::ip::make_address_v4(netAddress.toString())) {
    // cppcheck-suppress useInitializationList
    netmask_ = boost::asio::ip::address_v4(
        (subnet_mask == 0)
            ? 0
            : (~static_cast<std::uint32_t>(0) << (32 - subnet_mask)));

    uint32_t ip_num = ip_.to_uint();
    uint32_t netmask_num = netmask_.to_uint();

    uint32_t network_address = ip_num & netmask_num;
    broadcast_ =
        boost::asio::ip::address_v4(network_address | ~netmask_.to_uint());

    num_available_addresses_ = (1U << (32 - subnet_mask)) - 2;
  }

  std::uint32_t NumAvailableAddresses() const noexcept {
    return num_available_addresses_;
  }

  pcpp::IPv4Address GetNextAddress() noexcept {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    const std::uint32_t new_ip = ip_.to_uint() + 1;
    if (new_ip < broadcast_.to_uint()) {
      ip_ = boost::asio::ip::address_v4(new_ip);
    } else {
      ip_ = boost::asio::ip::address_v4(net_addr_.to_uint() + 1);
    }
    return pcpp::IPv4Address(ip_.to_string());
  }

 private:
  mutable std::mutex mutex_;
  boost::asio::ip::address_v4 ip_;
  boost::asio::ip::address_v4 net_addr_;

  boost::asio::ip::address_v4 netmask_;
  boost::asio::ip::address_v4 broadcast_;

  std::uint32_t num_available_addresses_;
};
using IPv4AddressGeneratorSPtr = std::shared_ptr<IPv4AddressGenerator>;
}  // namespace fptn::common::network
