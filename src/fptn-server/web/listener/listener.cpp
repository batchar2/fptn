#include <spdlog/spdlog.h>

#include "listener.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/beast/core.hpp>

using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::use_awaitable;
namespace this_coro = boost::asio::this_coro;

using namespace fptn::web;


Listener::Listener(
    boost::asio::io_context& ioc,
    std::uint16_t port,
    const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
    WebSocketOpenConnectionCallback wsOpenCallback,
    WebSocketNewIPPacketCallback wsNewIPCallback,
    WebSocketCloseConnectionCallback wsCloseCallback
)
    :
        isRunning_(false),
        ioc_(ioc),
        ctx_(boost::asio::ssl::context::tlsv12),
        acceptor_(ioc_),
        tokenManager_(tokenManager),
        wsOpenCallback_(wsOpenCallback),
        wsNewIPCallback_(wsNewIPCallback),
        wsCloseCallback_(wsCloseCallback),
        endpoint_(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)) //,

{
    ctx_.set_options(boost::asio::ssl::context::default_workarounds
                     | boost::asio::ssl::context::no_sslv2
                     | boost::asio::ssl::context::no_sslv3
                     | boost::asio::ssl::context::single_dh_use);

    ctx_.use_certificate_chain_file(tokenManager->serverCrtPath());
    ctx_.use_private_key_file(tokenManager->serverKeyPath(), boost::asio::ssl::context::pem);

    // openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
    // ctx_.use_certificate_chain_file("/etc/fptn/cert.pem");
    // ctx_.use_private_key_file("/etc/fptn/key.pem", boost::asio::ssl::context::pem);
    ctx_.set_verify_mode(boost::asio::ssl::verify_none);  // For development only! Avoid in production
}

void Listener::httpRegister(const std::string& url, const std::string& method, const ApiHandle& handle)
{
    addApiHandle(apiHandles_, url, method, handle);
}

boost::asio::awaitable<void> Listener::run()
{
    try {
        acceptor_.open(endpoint_.protocol());
        acceptor_.set_option(boost::asio::ip::tcp::no_delay(true));
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
        acceptor_.bind(endpoint_);
        acceptor_.listen(boost::asio::socket_base::max_listen_connections);
    } catch (boost::system::system_error& err) {
        spdlog::error("Listener::prepare error: {}", err.what());
        co_return;
    }
    isRunning_ = true;

    boost::system::error_code ec;
    while (isRunning_) {
        try {
            boost::asio::ip::tcp::socket socket(ioc_);
            co_await acceptor_.async_accept(
                socket,
                boost::asio::redirect_error(boost::asio::use_awaitable, ec)
            );
            if (!ec) {
                auto session = std::make_shared<Session>(
                    std::move(socket),
                    ctx_,
                    apiHandles_,
                    wsOpenCallback_,
                    wsNewIPCallback_,
                    wsCloseCallback_
                );
                // run coroutine
                boost::asio::co_spawn(
                    ioc_,
                    [session]() -> boost::asio::awaitable<void> {
                        co_await session->run();
                    },
                    boost::asio::detached
                );
            } else {
                spdlog::error("Error onAccept: {}", ec.message());
            }
        } catch (boost::system::system_error& err) {
            spdlog::error("Listener::run error: {}", err.what());
            co_return;
        }
    }
    co_return;
}

bool Listener::stop()
{
    try {
        acceptor_.close();
    } catch (boost::system::system_error& err) {
        spdlog::error("Listener::stop error: {}", err.what());
        return false;
    }
    return true;
}
