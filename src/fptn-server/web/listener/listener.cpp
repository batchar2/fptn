/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/listener/listener.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

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

Listener::Listener(Config config)
    : config_(std::move(config)),
      ctx_(boost::asio::ssl::context::tlsv13_server),
      acceptor_(config_.ioc),
      endpoint_(boost::asio::ip::tcp::endpoint(
          boost::asio::ip::tcp::v4(), config_.port)),
      running_(false) {
  ctx_.set_options(boost::asio::ssl::context::default_workarounds |
                   boost::asio::ssl::context::no_sslv2 |
                   boost::asio::ssl::context::no_sslv3 |
                   boost::asio::ssl::context::single_dh_use);
  ctx_.use_certificate_chain_file(config_.token_manager->ServerCrtPath());
  ctx_.use_private_key_file(
      config_.token_manager->ServerKeyPath(), boost::asio::ssl::context::pem);
  ctx_.set_verify_mode(boost::asio::ssl::verify_none);
}

void Listener::AddApiHandle(const std::string& url,
    const std::string& method,
    const ApiHandle& handle) {
  fptn::web::AddApiHandle(api_handles_, url, method, handle);
}

boost::asio::awaitable<void> Listener::Run() {
  constexpr int kBufferSize = 4 * 1024 * 1024;
  try {
    acceptor_.open(endpoint_.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::no_delay(true));
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true));

    // Optimize socket buffers for high throughput (1 Gbit/s+)
    // Set send/recv buffers to 4MB (typical for high-speed WAN)
    acceptor_.set_option(
        boost::asio::socket_base::receive_buffer_size(kBufferSize));
    acceptor_.set_option(
        boost::asio::socket_base::send_buffer_size(kBufferSize));

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
      boost::asio::ip::tcp::socket socket(config_.ioc);
      co_await acceptor_.async_accept(
          socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

      if (!ec) {
        // Propagate buffer settings to the accepted socket
        socket.set_option(boost::asio::ip::tcp::no_delay(true));
        socket.set_option(
            boost::asio::socket_base::receive_buffer_size(kBufferSize));
        socket.set_option(
            boost::asio::socket_base::send_buffer_size(kBufferSize));

        auto session =
            std::make_shared<Session>(Session::Config{.port = config_.port,
                .enable_detect_probing = config_.enable_detect_probing,
                .default_proxy_domain = config_.default_proxy_domain,
                .allowed_sni_list = config_.allowed_sni_list,
                .server_external_ips = config_.server_external_ips,
                .socket = std::move(socket),
                .ctx = ctx_,
                .api_handles = api_handles_,
                .handshake_cache_manager = config_.handshake_cache_manager,
                .on_ws_open_callback = config_.on_ws_open_callback,
                .on_ws_new_ip_packet_callback =
                    config_.on_ws_new_ip_packet_callback,
                .on_ws_close_callback = config_.on_ws_close_callback});
        // run coroutine
        boost::asio::co_spawn(
            config_.ioc,
            [session]() mutable -> boost::asio::awaitable<void> {
              co_await session->Run();
            },
            boost::asio::detached);
      } else if (running_) {
        SPDLOG_ERROR("Error onAccept: {}", ec.message());
        // Add delay after exception
        boost::asio::steady_timer timer(config_.ioc);
        timer.expires_after(std::chrono::milliseconds(300));
        co_await timer.async_wait(boost::asio::use_awaitable);
      }
    } catch (boost::system::system_error& err) {
      if (running_) {
        SPDLOG_ERROR("Listener::run error: {}", err.what());
      }
      co_return;
    }
  }
  co_return;
}

bool Listener::Stop() {
  try {
    running_ = false;
    acceptor_.close();
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Listener::stop error: {}", err.what());
    return false;
  }
  return true;
}
