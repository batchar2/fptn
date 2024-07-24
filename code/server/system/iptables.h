#pragma once

#include <string>
#include <memory>

namespace fptn::system
{
    class IPTables final
    {
    public:
        IPTables(
            const std::string& outInterfaceName,
            const std::string& tunInterfaceName
        );
        ~IPTables();
        bool check() noexcept;
        bool apply() noexcept;
        bool clean() noexcept;
    private:
        bool init_;
        std::string outInterfaceName_;
        std::string tunInterfaceName_;
    };

    using IPTablesPtr = std::unique_ptr<IPTables>;
}
