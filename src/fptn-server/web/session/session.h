/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/coroutine/all.hpp>
#include <openssl/err.h>   // NOLINT(build/include_order)
#include <openssl/ssl.h>   // NOLINT(build/include_order)
#include <openssl/x509.h>  // NOLINT(build/include_order)

#include "common/jwt_token/token_manager.h"
#include "common/protobuf/protocol.h"

#include "web/api/handle.h"

namespace fptn::web {

class Session : public std::enable_shared_from_this<Session> {
 public:
  explicit Session(boost::asio::ip::tcp::socket&& socket,
      boost::asio::ssl::context& ctx,
      const ApiHandleMap& api_handles,
      WebSocketOpenConnectionCallback ws_open_callback,
      WebSocketNewIPPacketCallback ws_new_ippacket_callback,
      WebSocketCloseConnectionCallback ws_close_callback);
  virtual ~Session();
  void Close();

  // async
  boost::asio::awaitable<void> Run();
  boost::asio::awaitable<bool> Send(fptn::common::network::IPPacketPtr packet);

 protected:
  boost::asio::awaitable<void> RunReader();
  boost::asio::awaitable<void> RunSender();

 protected:
  boost::asio::awaitable<std::pair<bool, std::string>> DetectProbing();
  boost::asio::awaitable<bool> HandleProxy(const std::string& sni, int port);

 protected:
  boost::asio::awaitable<bool> ProcessRequest();
  boost::asio::awaitable<bool> HandleHttp(
      const boost::beast::http::request<boost::beast::http::string_body>&
          request);
  boost::asio::awaitable<bool> HandleWebSocket(
      const boost::beast::http::request<boost::beast::http::string_body>&
          request);

 private:
  mutable std::mutex mutex_;

  fptn::ClientID client_id_ = MAX_CLIENT_ID;

  boost::beast::websocket::stream<
      boost::asio::ssl::stream<boost::beast::tcp_stream>>
      ws_;
  boost::asio::strand<boost::asio::any_io_executor> strand_;
  boost::asio::experimental::concurrent_channel<void(
      boost::system::error_code, fptn::common::network::IPPacketPtr)>
      write_channel_;

  const ApiHandleMap& api_handles_;
  const WebSocketOpenConnectionCallback ws_open_callback_;
  const WebSocketNewIPPacketCallback ws_new_ippacket_callback_;
  const WebSocketCloseConnectionCallback ws_close_callback_;

  std::atomic<bool> running_;
  bool init_completed_;
  std::atomic<bool> full_queue_;
};

using SessionSPtr = std::shared_ptr<Session>;
}  // namespace fptn::web
