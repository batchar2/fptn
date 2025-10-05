/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>

#include <queue>

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/obfuscator/socket/socket.h"
#include "fptn-protocol-lib/https/obfuscator/socket_wrapper/socket_wrapper.h"

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

 protected:
  void onResolve(boost::beast::error_code ec,
      const boost::asio::ip::tcp::resolver::results_type& results);
  void onConnect(boost::beast::error_code ec);
  void onSslHandshake(boost::beast::error_code ec);
  void onHandshake(boost::beast::error_code ec);
  void onWrite(boost::beast::error_code ec, std::size_t bytes_transferred);
  void onRead(boost::beast::error_code ec, std::size_t transferred);

 protected:
  void DoRead();
  void DoWrite();
  void Fail(boost::beast::error_code ec, char const* what);

 private:
  obfuscator::Socket& get_socket() { return *socket_; }
  obfuscator::SocketWrapper& get_socket_wrapper() { return *socket_wrapper_; }

  const std::string kUrlWebSocket_ = "/fptn";
  const std::size_t kMaxSizeOutQueue_ = 128;

  std::thread th_;
  mutable std::mutex mutex_;
  mutable std::queue<fptn::common::network::IPPacketPtr> out_queue_;

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
  boost::beast::flat_buffer buffer_;

  mutable std::atomic<bool> running_;
  mutable std::atomic<bool> was_connected_;

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
