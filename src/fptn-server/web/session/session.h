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

#include "fptn-protocol-lib/https/obfuscator/socket/socket.h"
#include "web/api/handle.h"

namespace fptn::web {

class Session : public std::enable_shared_from_this<Session> {
 public:
  explicit Session(std::uint16_t port,
      bool enable_detect_probing,
      boost::asio::ip::tcp::socket&& socket,
      boost::asio::ssl::context& ctx,
      const ApiHandleMap& api_handles,
      WebSocketOpenConnectionCallback ws_open_callback,
      WebSocketNewIPPacketCallback ws_new_ippacket_callback,
      WebSocketCloseConnectionCallback ws_close_callback,
      fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator = nullptr);
  virtual ~Session();
  void Close();

  // async
  boost::asio::awaitable<void> Run();
  boost::asio::awaitable<bool> Send(fptn::common::network::IPPacketPtr packet);

 protected:
  boost::asio::awaitable<void> RunReader();
  boost::asio::awaitable<void> RunSender();

 protected:
  struct ProbingResult {
    bool is_probing;
    std::string sni;
    bool should_close;
  };

  boost::asio::awaitable<ProbingResult> DetectProbing();
  boost::asio::awaitable<bool> IsSniSelfProxyAttempt(
      const std::string& sni) const;
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

  const std::uint16_t port_;
  const bool enable_detect_probing_;

  fptn::protocol::https::obfuscator::SocketSPtr socket_;

  using ssl_socket_stream =
      boost::asio::ssl::stream<fptn::protocol::https::obfuscator::Socket&>;
  std::unique_ptr<ssl_socket_stream> ssl_stream_;

  std::unique_ptr<boost::beast::websocket::stream<ssl_socket_stream&>> ws_;

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
  bool ws_session_was_opened_;
  std::atomic<bool> full_queue_;

  boost::asio::cancellation_signal cancel_signal_;
};

using SessionSPtr = std::shared_ptr<Session>;
}  // namespace fptn::web
