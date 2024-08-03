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
            fptn::web::ServerSPtr webServer, 
            fptn::network::VirtualInterfaceSPtr networkInterface,
            fptn::nat::TableSPtr nat,
            fptn::filter::FilterManagerSPtr filter
        );
        ~Manager();
        bool stop() noexcept;
        bool start() noexcept;
    private:
        void runToClient() noexcept;
        void runFromClient() noexcept;
    private:
        std::atomic<bool> running_ = false; 
        fptn::web::ServerSPtr webServer_;
        fptn::network::VirtualInterfaceSPtr networkInterface_;
        fptn::nat::TableSPtr nat_;
        fptn::filter::FilterManagerSPtr filter_;

        std::thread readToClientThread_;
        std::thread readFromClientThread_;
    };
}