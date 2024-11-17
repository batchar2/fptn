#pragma once

#include <string>
#include <memory>
#include <cinttypes>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>


namespace fptn::common::network
{

    class IPAddressGenerator {
    public:
        IPAddressGenerator(const pcpp::IPv4Address &netAddress, std::uint32_t subnetMask)
        {
            // Boost is more convenient for calculations.
            // In the future, only pcpp::IPv4Address should be used.

            ip_ = boost::asio::ip::address_v4::from_string(netAddress.toString());
            netAddr_ = boost::asio::ip::address_v4::from_string(netAddress.toString());
            netmask_ = boost::asio::ip::address_v4((subnetMask == 0) ? 0 : (~uint32_t(0) << (32 - subnetMask)));

            uint32_t ip_num = ip_.to_uint();
            uint32_t netmask_num = netmask_.to_uint();

            uint32_t network_address = ip_num & netmask_num;
            broadcast_ = boost::asio::ip::address_v4(network_address | ~netmask_.to_uint());

            numAvailableAddresses_ = (1U << (32 - subnetMask)) - 2;
        }
        const std::uint32_t numAvailableAddresses() const
        {
            return numAvailableAddresses_;
        }
        pcpp::IPv4Address getNextAddress()
        {
            std::unique_lock<std::mutex> lock(mutex_);
            const std::uint32_t newIP = ip_.to_uint() + 1;
            if (newIP < broadcast_.to_uint()) {
                ip_ = boost::asio::ip::address_v4(newIP);
            } else {
                ip_ = boost::asio::ip::address_v4(netAddr_.to_uint() + 1);
            }
            return pcpp::IPv4Address(ip_.to_string());
        }
        bool isAddressInRange(const pcpp::IPv4Address &address) const
        {
            const std::uint32_t addr = address.toInt();
            const std::uint32_t network = netAddr_.to_uint();
            const std::uint32_t mask = netmask_.to_uint();
            return (addr & mask) == (network & mask) &&
                    addr >= network + 1 &&
                    addr <= broadcast_.to_uint() - 1;
        }
    private:
        mutable std::mutex mutex_;
        boost::asio::ip::address_v4 ip_;
        boost::asio::ip::address_v4 netAddr_;

        boost::asio::ip::address_v4 netmask_;
        boost::asio::ip::address_v4 broadcast_;

        std::uint32_t numAvailableAddresses_;
    };
    using IPAddressGeneratorSPtr = std::shared_ptr<IPAddressGenerator>;
}
