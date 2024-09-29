#pragma once

#include <string>
#include <memory>
#include <iostream>

#include <pcapplusplus/IpAddress.h>


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
            const pcpp::IPv4Address& dnsServer,
            const pcpp::IPv4Address& gatewayIp,
            const pcpp::IPv4Address tunInterfaceAddress=pcpp::IPv4Address("10.10.10.1")
        );
        ~IPTables();
        bool check() noexcept;
        bool apply() noexcept;
        bool clean() noexcept;
    private:
        bool init_;
        const std::string outInterfaceName_;
        const std::string tunInterfaceName_;
        const pcpp::IPv4Address vpnServerIP_;
        const pcpp::IPv4Address dnsServer_;
        const pcpp::IPv4Address gatewayIp_;
        const pcpp::IPv4Address tunInterfaceAddress_;
    private:
        std::string findOutInterfaceName_;
        pcpp::IPv4Address findOutGatewayIp_;
    };

    using IPTablesPtr = std::unique_ptr<IPTables>;
}
