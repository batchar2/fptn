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
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/obfuscator/socket/socket.h"
#include "fptn-protocol-lib/https/obfuscator/socket_wrapper/socket_wrapper.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/protobuf/protocol.h"

namespace fptn::protocol::https {

class WebsocketClient : public std::enable_shared_from_this<WebsocketClient> {
  using NewIPPacketCallback =
      std::function<void(fptn::common::network::IPPacketPtr packet)>;
  using OnConnectedCallback = std::function<void()>;

 public:
  explicit WebsocketClient(pcpp::IPv4Address server_ip,
      int server_port,
      pcpp::IPv4Address tun_interface_address_ipv4,
      pcpp::IPv6Address tun_interface_address_ipv6,
      NewIPPacketCallback new_ip_pkt_callback,
      std::string sni,
      std::string access_token,
      std::string expected_md5_fingerprint,
      fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator,
      OnConnectedCallback on_connected_callback = nullptr);

  virtual ~WebsocketClient();

 public:
  void Run();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet);
  bool IsStarted();

 private:
  boost::asio::awaitable<void> RunClient();
  boost::asio::awaitable<void> RunReader();
  boost::asio::awaitable<void> RunSender();
  void Fail(boost::system::error_code ec, char const* what);

 private:
  const std::string kUrlWebSocket_ = "/fptn";
  const std::size_t kMaxSizeOutQueue_ = 128;

  boost::asio::io_context ioc_;
  boost::asio::ssl::context ctx_;
  boost::asio::ip::tcp::resolver resolver_;

  obfuscator::IObfuscatorSPtr obfuscator_;
  obfuscator::SocketSPtr socket_;
  obfuscator::SocketWrapperSPtr socket_wrapper_;

  using ssl_socket_stream = boost::asio::ssl::stream<obfuscator::SocketWrapper>;
  std::unique_ptr<ssl_socket_stream> ssl_stream_;
  boost::beast::websocket::stream<ssl_socket_stream&> ws_;

  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  boost::asio::experimental::concurrent_channel<void(
      boost::system::error_code, fptn::common::network::IPPacketPtr)>
      write_channel_;

  boost::asio::cancellation_signal cancel_signal_;

  std::atomic<bool> running_{false};
  std::atomic<bool> was_connected_{false};

  const pcpp::IPv4Address server_ip_;
  const std::string server_port_str_;

  const pcpp::IPv4Address tun_interface_address_ipv4_;
  const pcpp::IPv6Address tun_interface_address_ipv6_;
  const NewIPPacketCallback new_ip_pkt_callback_;
  const std::string sni_;
  const std::string access_token_;
  const std::string expected_md5_fingerprint_;

  OnConnectedCallback on_connected_callback_;

  SSL* ssl_{nullptr};
};

using WebsocketClientSPtr = std::shared_ptr<WebsocketClient>;

}  // namespace fptn::protocol::https
