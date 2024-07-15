#pragma once

#include <chrono>
#include <unordered_map>

#include <hv/WebSocketServer.h>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>

#ifdef TCPOPT_CC
#undef TCPOPT_CC
#endif // TCPOPT_CC
#ifdef TCPOPT_CCNEW
#undef TCPOPT_CCNEW
#endif // TCPOPT_CCNEW
#ifdef TCPOPT_CCECHO
#undef TCPOPT_CCECHO
#endif // TCPOPT_CCECHO

#include <pcapplusplus/TcpLayer.h>


namespace fptn::nat
{

    class client_session final
    {
    public:
        client_session(
            const pcpp::IPv4Address &client_real_ip,
            const pcpp::IPv4Address &client_vpn_ip,
            const WebSocketChannelPtr& ch
        );
        ~client_session() = default;
        bool from_client(pcpp::Packet &packet) noexcept;
        const WebSocketChannelPtr channel() noexcept;
        bool to_client(pcpp::Packet &packet) noexcept;
    private:
        pcpp::IPv4Address client_real_ip_;
        pcpp::IPv4Address client_vpn_ip_;
        const WebSocketChannelPtr channel_;
        std::chrono::steady_clock::time_point last_update_;
    };
}



