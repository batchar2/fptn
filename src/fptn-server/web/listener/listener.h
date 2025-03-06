#pragma once

#include <memory>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <common/jwt_token/token_manager.h>

#include "web/api/handle.h"
#include "web/session/session.h"


namespace fptn::web
{

    class Listener //: public std::enable_shared_from_this<Listener>
    {
    public:
        explicit Listener(
            boost::asio::io_context& ioc,
            std::uint16_t port,
            const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
            WebSocketOpenConnectionCallback wsOpenCallback,
            WebSocketNewIPPacketCallback wsNewIPCallback,
            WebSocketCloseConnectionCallback wsCloseCallback
        );
        //virtual ~Listener() = default;
        boost::asio::awaitable<void> run();
        bool stop();
        void httpRegister(const std::string& url, const std::string& method, const ApiHandle& handle);
    protected:
        std::atomic<bool> isRunning_;
        ApiHandleMap apiHandles_;

        boost::asio::io_context& ioc_;
        boost::asio::ssl::context ctx_;
        boost::asio::ip::tcp::acceptor acceptor_;

        fptn::common::jwt_token::TokenManagerSPtr tokenManager_;

        const WebSocketOpenConnectionCallback wsOpenCallback_;
        const WebSocketNewIPPacketCallback wsNewIPCallback_;
        const WebSocketCloseConnectionCallback wsCloseCallback_;

        boost::asio::ip::tcp::endpoint endpoint_;
    };

    using ListenerSPtr = std::shared_ptr<Listener>;
}
