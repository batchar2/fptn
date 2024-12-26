#pragma once

#include <mutex>
#include <memory>
#include <string>


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
        mutable std::mutex mutex_;

        bool init_;
        std::string outInterfaceName_;
        std::string tunInterfaceName_;
    };

    using IPTablesPtr = std::unique_ptr<IPTables>;
}
