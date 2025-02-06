#pragma once

#include <memory>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <common/protobuf/protocol.h>
#include <common/jwt_token/token_manager.h>

#include "web/api/handle.h"


namespace fptn::web {

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
        bool run() noexcept;
        void send(fptn::common::network::IPPacketPtr packet) noexcept;
        void close() noexcept;
    protected:
        void onRun();
        void onHandshake(boost::beast::error_code ec);
        void handleHttp();
        void onAccept(boost::beast::error_code ec);
        void doRead();
        void onRead(boost::beast::error_code ec, std::size_t bytes_transferred);
        void onWrite(boost::beast::error_code ec, std::size_t bytes_transferred);
        void onClose(boost::beast::error_code ec);
    private:
        boost::beast::websocket::stream<boost::asio::ssl::stream<boost::beast::tcp_stream>> ws_;
        const ApiHandleMap& apiHandles_;
        //boost::asio::steady_timer timer_;

        const WebSocketOpenConnectionCallback wsOpenCallback_;
        const WebSocketNewIPPacketCallback wsNewIPCallback_;
        const WebSocketCloseConnectionCallback wsCloseCallback_;

        boost::beast::flat_buffer incomingBuffer_;
        boost::beast::http::request<boost::beast::http::string_body> request_;

        fptn::ClientID clientId_ = MAX_CLIENT_ID;
    };

    using SessionSPtr = std::shared_ptr<Session>;
}
