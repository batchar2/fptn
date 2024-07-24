#pragma once

#include <mutex>
#include <thread>
#include <string>
#include <iostream>
#include <functional>

#include <hv/WebSocketClient.h>
#include <common/network/ip_packet.h>


namespace fptn::http
{
    class WebSocketClient final
    {
    public:
        using NewIPPacketCallback = std::function<void(fptn::common::network::IPPacketPtr packet)>;
    public:
        WebSocketClient(const std::string& url,
            const std::string& token,
            const std::string& interfaceAddress,
            bool useSsl = true,
            const NewIPPacketCallback& newIPPktCallback = nullptr
        );
        bool start() noexcept;
        bool stop() noexcept;
        bool send(fptn::common::network::IPPacketPtr packet) noexcept;
        void setNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept;
    private:
        void run() noexcept;
    private:
        void onOpenHandle() noexcept;
        void onMessageHandle(const std::string& msg) noexcept;
        void onCloseHandle() noexcept;
    private:
        std::thread th_;
        std::mutex mtx_;
        hv::WebSocketClient ws_;

        std::string url_;
        std::string token_;
        NewIPPacketCallback newIPPktCallback_;
    };

    using WebSocketClientPtr = std::unique_ptr<WebSocketClient>;
}
