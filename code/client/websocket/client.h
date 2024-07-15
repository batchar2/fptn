#pragma once

#include <mutex>
#include <thread>
#include <string>
#include <iostream>
#include <functional>

#include <hv/WebSocketClient.h>


namespace fptn::websocket
{
    class client final
    {
    public:
        using recv_packet_callback = std::function<void(const std::string& raw_ip_data)>;
    public:
        client(const std::string& url,
            const std::string& token,
            const std::string& interface_address,
            bool use_ssl = true,
            const recv_packet_callback& recv_packet = nullptr
        );
        bool start(const recv_packet_callback& recv_packet = nullptr) noexcept;
        bool stop() noexcept;
        bool send(const std::string& msg) noexcept;
    private:
        void run() noexcept;
    private:
        void on_open_handle() noexcept;
        void on_message_handle(const std::string& msg) noexcept;
        void on_close_handle() noexcept;
    private:
        std::thread th_;
        std::mutex mtx_;
        hv::WebSocketClient ws_;

        std::string url_;
        std::string token_;
        recv_packet_callback recv_packet_callback_;
    };
}
