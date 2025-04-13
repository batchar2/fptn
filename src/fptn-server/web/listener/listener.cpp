/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/listener/listener.h"

#include <memory>
#include <string>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

using fptn::web::Listener;

Listener::Listener(boost::asio::io_context& ioc,
    std::uint16_t port,
    fptn::common::jwt_token::TokenManagerSPtr token_manager,
    WebSocketOpenConnectionCallback ws_open_callback,
    WebSocketNewIPPacketCallback ws_new_ippacket_callback,
    WebSocketCloseConnectionCallback ws_close_callback)
    : ioc_(ioc),
      ctx_(boost::asio::ssl::context::tlsv12),
      acceptor_(ioc_),
      token_manager_(std::move(token_manager)),
      ws_open_callback_(std::move(ws_open_callback)),
      ws_new_ippacket_callback_(std::move(ws_new_ippacket_callback)),
      ws_close_callback_(std::move(ws_close_callback)),
      endpoint_(
          boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      running_(false) {
  ctx_.set_options(boost::asio::ssl::context::default_workarounds |
                   boost::asio::ssl::context::no_sslv2 |
                   boost::asio::ssl::context::no_sslv3 |
                   boost::asio::ssl::context::single_dh_use);

  ctx_.use_certificate_chain_file(token_manager_->ServerCrtPath());
  ctx_.use_private_key_file(
      token_manager_->ServerKeyPath(), boost::asio::ssl::context::pem);

  // openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
  // -nodes ctx_.use_certificate_chain_file("/etc/fptn/cert.pem");
  // ctx_.use_private_key_file("/etc/fptn/key.pem",
  // boost::asio::ssl::context::pem);
  ctx_.set_verify_mode(boost::asio::ssl::verify_none);  // For development only!
                                                        // Avoid in production
}

void Listener::httpRegister(const std::string& url,
    const std::string& method,
    const ApiHandle& handle) {
  AddApiHandle(api_handles_, url, method, handle);
}

boost::asio::awaitable<void> Listener::run() {
  try {
    acceptor_.open(endpoint_.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::no_delay(true));
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
    acceptor_.bind(endpoint_);
    acceptor_.listen(boost::asio::socket_base::max_listen_connections);
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Listener::prepare error: {}", err.what());
    co_return;
  }
  running_ = true;

  boost::system::error_code ec;
  while (running_) {
    try {
      boost::asio::ip::tcp::socket socket(ioc_);
      co_await acceptor_.async_accept(
          socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (!ec) {
        auto session = std::make_shared<Session>(std::move(socket), ctx_,
            api_handles_, ws_open_callback_, ws_new_ippacket_callback_,
            ws_close_callback_);
        // run coroutine
        boost::asio::co_spawn(
            ioc_,
            [session]() mutable -> boost::asio::awaitable<void> {
              co_await session->Run();
            },
            boost::asio::detached);
      } else {
        SPDLOG_ERROR("Error onAccept: {}", ec.message());
      }
    } catch (boost::system::system_error& err) {
      SPDLOG_ERROR("Listener::run error: {}", err.what());
      co_return;
    }
  }
  co_return;
}

bool Listener::stop() {
  try {
    acceptor_.close();
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Listener::stop error: {}", err.what());
    return false;
  }
  return true;
}
