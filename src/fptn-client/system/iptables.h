#pragma once

#include <string>
#include <memory>
#include <iostream>


namespace fptn::system
{
    std::string getDefaultGatewayIPAddress();

    class IPTables final
    {
    public:
        IPTables(
            const std::string& outInterfaceName,
            const std::string& tunInterfaceName,
            const std::string& vpnServerIP,
            const std::string& gatewayIp="",
            const std::string& tunInterfaceAddress="10.10.10.1"
        );
        ~IPTables();
        bool check() noexcept;
        bool apply() noexcept;
        bool clean() noexcept;
    private:
        bool init_;
        std::string outInterfaceName_;
        std::string tunInterfaceName_;
        std::string vpnServerIp_;
        std::string gatewayIp_;
        std::string tunInterfaceAddress_;
    };

    using IPTablesPtr = std::unique_ptr<IPTables>;
}
