#pragma once

#include <boost/asio/awaitable.hpp>

#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>


#include <boost/coroutine/all.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>


#include <common/protobuf/protocol.h>
#include <common/jwt_token/token_manager.h>

#include "web/api/handle.h"


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
        virtual ~Session();
        void close() noexcept;

        // async
        boost::asio::awaitable<void> run() noexcept;
        boost::asio::awaitable<bool> send(fptn::common::network::IPPacketPtr packet) noexcept;
    protected:
        boost::asio::awaitable<void> runReader() noexcept;
        boost::asio::awaitable<void> runSender() noexcept;

        boost::asio::awaitable<bool> processRequest() noexcept;
        boost::asio::awaitable<bool> handleHttp(const boost::beast::http::request<boost::beast::http::string_body>& request) noexcept;
        boost::asio::awaitable<bool> handleWebSocket(const boost::beast::http::request<boost::beast::http::string_body>& request) noexcept;
    private:
        std::mutex mutex_;
        fptn::ClientID clientId_ = MAX_CLIENT_ID;

        std::atomic<bool> isRunning_;

        boost::beast::websocket::stream<boost::asio::ssl::stream<boost::beast::tcp_stream>> ws_;
        boost::asio::strand<boost::asio::any_io_executor> strand_;
//        boost::asio::experimental::concurrent_channel<void()> write_lock_;
        boost::asio::experimental::concurrent_channel<void(boost::system::error_code, fptn::common::network::IPPacketPtr)> write_channel_;
        const ApiHandleMap& apiHandles_;
        const WebSocketOpenConnectionCallback wsOpenCallback_;
        const WebSocketNewIPPacketCallback wsNewIPCallback_;
        const WebSocketCloseConnectionCallback wsCloseCallback_;

        bool isInitComplete_;
    };

    using SessionSPtr = std::shared_ptr<Session>;
}
