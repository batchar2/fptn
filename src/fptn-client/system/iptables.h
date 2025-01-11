#pragma once

#include <mutex>
#include <memory>
#include <string>
#include <iostream>

#if _WIN32
#pragma warning(disable: 4996) 
#endif

#include <pcapplusplus/IpAddress.h>

#if _WIN32
#pragma warning(default: 4996) 
#endif


namespace fptn::system
{
    std::string getDefaultNetworkInterfaceName() noexcept;
    pcpp::IPv4Address getDefaultGatewayIPAddress() noexcept;
    pcpp::IPv4Address resolveDomain(const std::string& domain) noexcept;

    class IPTables final
    {
    public:
        IPTables(
            const std::string& outInterfaceName,
            const std::string& tunInterfaceName,
            const pcpp::IPv4Address& vpnServerIP,
            const pcpp::IPv4Address& dnsServerIPv4,
            const pcpp::IPv6Address& dnsServerIPv6,
            const pcpp::IPv4Address& gatewayIp,
            const pcpp::IPv4Address& tunInterfaceAddressIPv4,
            const pcpp::IPv6Address& tunInterfaceAddressIPv6
        );
        ~IPTables();
        bool check() noexcept;
        bool apply() noexcept;
        bool clean() noexcept;
    private:
        mutable std::mutex mutex_;

        bool init_;
        const std::string outInterfaceName_;
        const std::string tunInterfaceName_;
        const pcpp::IPv4Address vpnServerIP_;
        const pcpp::IPv4Address dnsServerIPv4_;
        const pcpp::IPv6Address dnsServerIPv6_;
        const pcpp::IPv4Address gatewayIp_;
        const pcpp::IPv4Address tunInterfaceAddressIPv4_;
        const pcpp::IPv6Address tunInterfaceAddressIPv6_;
    private:
        std::string findOutInterfaceName_;
        pcpp::IPv4Address findOutGatewayIp_;
    };

    using IPTablesPtr = std::unique_ptr<IPTables>;
}