#pragma once

#include <string>
#include <memory>
#include <iostream>


namespace fptn::system
{
    class IPTables final
    {
    public:
        IPTables(
            const std::string& outInterfaceName,
            const std::string& tunInterfaceName,
            const std::string& vpnServerIP,
            const std::string& gatewayIp=""
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
    };

    using IPTablesPtr = std::unique_ptr<IPTables>;
}
