#pragma once

//#define BOOST_ASIO_USE_TS_EXECUTOR_AS_DEFAULT
#include <boost/asio/awaitable.hpp>

#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/beast/core.hpp>

#include <boost/coroutine/all.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>


#include <common/protobuf/protocol.h>
#include <common/jwt_token/token_manager.h>

#include "web/api/handle.h"

#include <boost/asio.hpp>

#include <boost/asio/awaitable.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <boost/asio/experimental/channel.hpp>





namespace fptn::web
{

    class Session : public std::enable_shared_from_this<Session>
    {
    public:
        explicit Session(
            boost::asio::ip::tcp::socket&& socket,
            boost::asio::ssl::context& ctx,
            const ApiHandleMap& apiHandles,
            WebSocketOpenConnectionCallback wsOpenCallback,
            WebSocketNewIPPacketCallback wsNewIPCallback,
            WebSocketCloseConnectionCallback wsCloseCallback
        );
        boost::asio::awaitable<void> run();
        void close() noexcept;
        void send(fptn::common::network::IPPacketPtr packet) noexcept;
    protected:
        boost::asio::awaitable<bool> handshake();
        boost::asio::awaitable<bool> handleHttp(const boost::beast::http::request<boost::beast::http::string_body>& request);
        boost::asio::awaitable<bool> handleWebSocket(const boost::beast::http::request<boost::beast::http::string_body>& request);
    protected:
        fptn::ClientID clientId_ = MAX_CLIENT_ID;

        std::atomic<bool> isRunning_;

        boost::beast::websocket::stream<boost::asio::ssl::stream<boost::beast::tcp_stream>> ws_;
        const ApiHandleMap& apiHandles_;
        const WebSocketOpenConnectionCallback wsOpenCallback_;
        const WebSocketNewIPPacketCallback wsNewIPCallback_;
        const WebSocketCloseConnectionCallback wsCloseCallback_;
    };

    using SessionSPtr = std::shared_ptr<Session>;
}
