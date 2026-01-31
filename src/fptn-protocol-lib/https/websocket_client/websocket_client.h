/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/connection_config.h"
#include "fptn-protocol-lib/https/obfuscator/tcp_stream/tcp_stream.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/protobuf/protocol.h"

namespace fptn::protocol::https {

class WebsocketClient : public std::enable_shared_from_this<WebsocketClient> {
 public:
  explicit WebsocketClient(std::string jwt_access_token,
      ConnectionConfig config,
      int thread_number = 4);

  virtual ~WebsocketClient();

  WebsocketClient(const WebsocketClient&) = delete;
  WebsocketClient& operator=(const WebsocketClient&) = delete;
  WebsocketClient(WebsocketClient&&) = delete;
  WebsocketClient& operator=(WebsocketClient&&) = delete;

  void Run();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet);
  bool IsStarted() const;

 protected:
  boost::asio::awaitable<bool> RunInternal();
  boost::asio::awaitable<void> RunReader();
  boost::asio::awaitable<void> RunSender();
  boost::asio::awaitable<bool> Connect();

  boost::asio::awaitable<bool> PerformFakeHandshake();

  void StartWatchdog();

 private:
  const std::string kUrlWebSocket_ = "/fptn";
  const std::size_t kMaxSizeOutQueue_ = 128;

  mutable std::mutex mutex_;
  std::atomic<bool> running_{false};
  std::atomic<bool> was_stopped_{false};
  std::atomic<bool> was_inited_{false};
  std::atomic<bool> was_connected_{false};

  boost::asio::io_context ioc_;
  boost::asio::ssl::context ctx_;
  boost::asio::ip::tcp::resolver resolver_;

  boost::asio::cancellation_signal cancel_signal_;

  // TCP -> obfuscator -> SSL -> WebSocket
  using tcp_stream_type = boost::beast::tcp_stream;
  using obfuscator_socket_type = obfuscator::TcpStream<tcp_stream_type>;
  using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;
  using websocket_type = boost::beast::websocket::stream<ssl_stream_type>;
  websocket_type ws_;

  boost::asio::strand<boost::asio::io_context::executor_type> strand_;

  boost::asio::steady_timer watchdog_timer_;

  boost::asio::experimental::concurrent_channel<void(
      boost::system::error_code, fptn::common::network::IPPacketPtr)>
      write_channel_;

  const std::string jwt_access_token_;
  const ConnectionConfig config_;

  obfuscator::IObfuscatorSPtr obfuscator_;
};

using WebsocketClientPtr = std::shared_ptr<WebsocketClient>;

}  // namespace fptn::protocol::https
