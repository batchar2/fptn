#pragma once

#include <chrono>
#include <unordered_map>

#include "client_session/client_session.h"


namespace fptn::nat 
{

    class table final
    {
    public:
        table(const pcpp::IPv4Address &vpn_client_network, std::uint32_t vpn_network_mask);
        bool add_client(const pcpp::IPv4Address &client_ip, const WebSocketChannelPtr& channel, std::uint32_t client_id) noexcept;
        bool del_client(std::uint32_t client_id) noexcept;
        bool from_client(pcpp::Packet &packet, std::uint32_t client_id) noexcept;
        WebSocketChannelPtr to_client(pcpp::Packet &packet) noexcept; // TODO 
    private:
        std::mutex mtx_;
        const pcpp::IPv4Address vpn_client_network_;
        const std::uint32_t vpn_network_mask_;
        
        std::uint32_t network_host_pointer_;
        
        std::unordered_map<std::uint32_t, std::uint32_t> clientid_fackeip;
        std::unordered_map<std::uint32_t, std::shared_ptr<client_session>> fackeip_sessions_;
    };

}
