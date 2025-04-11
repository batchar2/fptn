/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4996)
#pragma warning(disable : 4267)
#pragma warning(disable : 4244)
#pragma warning(disable : 4702)
// #pragma warning(disable: 2220)  // Disable "warning treated as error"
#endif

#include <boost/asio/buffer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#ifdef _WIN32
#pragma warning(pop)
#endif

#include "common/network/ip_packet.h"

namespace fptn::http {
class Websocket : public std::enable_shared_from_this<Websocket> {
 public:
  using NewIPPacketCallback =
      std::function<void(fptn::common::network::IPPacketPtr packet)>;
  explicit Websocket(const pcpp::IPv4Address& server_ip,
      int server_port,
      const pcpp::IPv4Address& tun_interface_address_ipv4,
      const pcpp::IPv6Address& tun_interface_address_ipv6,
      const NewIPPacketCallback& new_ip_pkt_callback,
      const std::string& sni,
      const std::string& token);
  void Run() noexcept;
  bool Stop() noexcept;
  bool Send(fptn::common::network::IPPacketPtr packet) noexcept;
  bool IsStarted() noexcept;

 protected:
  void onResolve(boost::beast::error_code ec,
      boost::asio::ip::tcp::resolver::results_type results);
  void onConnect(boost::beast::error_code ec,
      boost::asio::ip::tcp::resolver::results_type::endpoint_type ep);
  void onSslHandshake(boost::beast::error_code ec);
  void onHandshake(boost::beast::error_code ec);
  void onWrite(boost::beast::error_code ec, std::size_t bytes_transferred);
  void onRead(boost::beast::error_code ec, std::size_t transferred);

  void doRead();
  void doWrite();
  void fail(boost::beast::error_code ec, char const* what) noexcept;

 private:
  boost::asio::io_context ioc_;
  boost::asio::ssl::context ctx_;
  boost::asio::ip::tcp::resolver resolver_;
  boost::beast::websocket::stream<
      boost::beast::ssl_stream<boost::beast::tcp_stream>>
      ws_;
  boost::asio::strand<boost::asio::io_context::executor_type> strand_;
  boost::beast::flat_buffer buffer_;

  const std::size_t out_queue_max_size_ = 128;
  mutable std::queue<fptn::common::network::IPPacketPtr> out_queue_;

  std::thread th_;
  mutable std::mutex mutex_;
  mutable std::atomic<bool> running_;

  const pcpp::IPv4Address server_ip_;
  const int server_port_;

  const pcpp::IPv4Address tun_interface_address_ipv4_;
  const pcpp::IPv6Address tun_interface_address_ipv6_;
  const NewIPPacketCallback new_ip_pkt_callback_;
  const std::string sni_;
  const std::string token_;
};

using WebsocketSPtr = std::shared_ptr<Websocket>;
}  // namespace fptn::http
