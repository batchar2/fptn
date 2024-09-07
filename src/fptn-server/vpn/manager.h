#pragma once 

#include <atomic>
#include <thread>

#include "nat/table.h"
#include "web/server.h"
#include "filter/manager.h"
#include "network/virtual_interface.h"


namespace fptn::vpn
{
    class Manager final
    {
    public:
        Manager(
            fptn::web::ServerPtr webServer,
            fptn::network::VirtualInterfacePtr networkInterface,
            const fptn::nat::TableSPtr& nat,
            const fptn::filter::FilterManagerSPtr& filter,
            const fptn::statistic::MetricsSPtr& prometheus
        );
        ~Manager();
        bool stop() noexcept;
        bool start() noexcept;
    private:
        void runToClient() noexcept;
        void runFromClient() noexcept;
        void runCollectStatistics() noexcept;
    private:
        std::atomic<bool> running_ = false; 
        fptn::web::ServerPtr webServer_;
        fptn::network::VirtualInterfacePtr networkInterface_;
        fptn::nat::TableSPtr nat_;
        fptn::filter::FilterManagerSPtr filter_;
        fptn::statistic::MetricsSPtr prometheus_;

        std::thread readToClientThread_;
        std::thread readFromClientThread_;
        std::thread collectStatistics_;
    };
}
