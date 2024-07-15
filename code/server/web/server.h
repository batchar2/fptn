#pragma once

#include "http/http.h"
#include "websocket/websocket.h"


namespace fptn::web
{
    class server final
    {
    public:
        server(
                std::uint16_t port,
                const bool use_https,
                const std::string& cert_file,
                const std::string& key_file,
                const websocket::new_connection_callback& new_connection = nullptr,
                const websocket::close_connection_callback& close_connection = nullptr,
                const int thread_number = 4
        );
        ~server();
        bool start(const websocket::recv_packet_callback &recv_packet = nullptr) noexcept;
        bool stop() noexcept;
    private:
        void run() noexcept;
    private:
        std::thread th_;
        std::mutex mtx_;

        http http_;
        websocket ws_;

        hv::WebSocketServer main_server_;
    };
}
