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
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/protobuf/protocol.h"

namespace fptn::protocol::https {

class WebsocketClient : public std::enable_shared_from_this<WebsocketClient> {
 public:
  using NewIPPacketCallback =
      std::function<void(fptn::common::network::IPPacketPtr packet)>;
  using OnConnectedCallback = std::function<void()>;

  WebsocketClient(pcpp::IPv4Address server_ip,
      int server_port,
      pcpp::IPv4Address tun_interface_address_ipv4,
      pcpp::IPv6Address tun_interface_address_ipv6,
      NewIPPacketCallback new_ip_pkt_callback,
      std::string sni,
      std::string access_token,
      std::string expected_md5_fingerprint,
      obfuscator::IObfuscatorSPtr obfuscator,
      OnConnectedCallback on_connected_callback = nullptr);

  virtual ~WebsocketClient();

  WebsocketClient(const WebsocketClient&) = delete;
  WebsocketClient& operator=(const WebsocketClient&) = delete;
  WebsocketClient(WebsocketClient&&) = delete;
  WebsocketClient& operator=(WebsocketClient&&) = delete;

 public:
  void Run();
  bool Stop();
  bool Send(fptn::common::network::IPPacketPtr packet);
  bool IsStarted();

 protected:
  void onResolve(const boost::beast::error_code& ec,
      const boost::asio::ip::tcp::resolver::results_type& results);
  void onConnect(const boost::beast::error_code& ec,
      const boost::asio::ip::tcp::resolver::results_type::endpoint_type& ep);
  void onSslHandshake(const boost::beast::error_code& ec);
  void onHandshake(const boost::beast::error_code& ec);
  void onWrite(
      const boost::beast::error_code& ec, std::size_t bytes_transferred);
  void onRead(const boost::beast::error_code& ec, std::size_t transferred);

 protected:
  void DoRead();
  void DoWrite();
  void Fail(const boost::beast::error_code& ec, const char* what);

  auto& get_obfuscator_layer() { return ws_.next_layer().next_layer(); }

 private:
  const std::string kUrlWebSocket_ = "/fptn";
  const std::size_t kMaxSizeOutQueue_ = 128;

  std::thread th_;
  mutable std::mutex mutex_;

  std::queue<fptn::common::network::IPPacketPtr> out_queue_;

  boost::asio::io_context ioc_;
  boost::asio::ssl::context ctx_;
  boost::asio::ip::tcp::resolver resolver_;

  // TCP -> obfuscator -> SSL -> WebSocket
  using tcp_stream_type = boost::beast::tcp_stream;
  using obfuscator_socket_type = obfuscator::obfuscator_socket<tcp_stream_type>;
  using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;
  using websocket_type = boost::beast::websocket::stream<ssl_stream_type>;
  obfuscator::IObfuscatorSPtr obfuscator_;
  websocket_type ws_;

  boost::beast::flat_buffer buffer_;

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
};

using WebsocketClientSPtr = std::shared_ptr<WebsocketClient>;

}  // namespace fptn::protocol::https
