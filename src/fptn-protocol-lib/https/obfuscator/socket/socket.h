/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <functional>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast.hpp>

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::protocol::https::obfuscator {

class Socket : public std::enable_shared_from_this<Socket> {
 public:
  using next_layer_type = boost::asio::ip::tcp::socket;
  using executor_type = next_layer_type::executor_type;
  using endpoint_type = next_layer_type::endpoint_type;
  using lowest_layer_type = next_layer_type;

  using strand_type = boost::asio::strand<executor_type>;

  explicit Socket(const executor_type& ex);
  explicit Socket(const executor_type& ex, IObfuscatorSPtr obfuscator);

  explicit Socket(next_layer_type&& socket);
  explicit Socket(next_layer_type&& socket, IObfuscatorSPtr obfuscator);

  void SetObfuscator(IObfuscatorSPtr obfuscator);

  next_layer_type& next_layer();
  const next_layer_type& next_layer() const;

  lowest_layer_type& lowest_layer();
  const lowest_layer_type& lowest_layer() const;

  executor_type get_executor();

  template <typename MutableBufferSequence, typename ReadHandler>
  void async_read_some(
      const MutableBufferSequence& buffers, ReadHandler&& handler) {
    auto self = shared_from_this();

    boost::asio::post(
        strand_, [self, buffers,
                     handler = std::forward<ReadHandler>(handler)]() mutable {
          self->socket_.async_read_some(buffers,
              [handler = std::move(handler)](boost::system::error_code ec,
                  std::size_t bytes_read) mutable {
                // std::cerr << "ar>" << bytes_read << std::endl;
                handler(ec, bytes_read);
              });
        });
  }
  template <typename ConstBufferSequence, typename WriteHandler>
  void async_write_some(
      const ConstBufferSequence& buffers, WriteHandler&& handler) {
    auto self = shared_from_this();

    boost::asio::post(
        strand_, [self, buffers,
                     handler = std::forward<WriteHandler>(handler)]() mutable {
          self->socket_.async_write_some(buffers,
              [handler = std::move(handler)](boost::system::error_code ec,
                  std::size_t bytes_write) mutable {
                // std::cerr << "aw>" << bytes_write << std::endl;
                handler(ec, bytes_write);
              });
        });
  }

  template <typename MutableBufferSequence>
  std::size_t read_some(
      const MutableBufferSequence& buffers, boost::system::error_code& ec) {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    const auto bites_read = socket_.read_some(buffers, ec);
    // std::cerr << "r>" << bites_read << std::endl;
    return bites_read;
  }

  template <typename ConstBufferSequence>
  std::size_t write_some(
      const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex
    const auto bites_write = socket_.write_some(buffers, ec);

    // std::cerr << "r>" << bites_write << std::endl;
    return bites_write;
  }

  template <typename ConnectHandler>
  void async_connect(
      const endpoint_type& peer_endpoint, ConnectHandler&& handler) {
    socket_.async_connect(peer_endpoint, std::forward<ConnectHandler>(handler));
  }

  void close(boost::system::error_code& ec);
  void close();

  bool is_open() const;

  endpoint_type remote_endpoint(boost::system::error_code& ec) const;
  endpoint_type local_endpoint(boost::system::error_code& ec) const;

  template <typename Option>
  void set_option(const Option& option) {
    // Для опций используем strand через post
    auto self = shared_from_this();
    boost::asio::post(
        strand_, [self, option]() { self->socket_.set_option(option); });
  }

  inline strand_type get_strand() const { return strand_; }

  void expires_after(std::chrono::steady_clock::duration timeout);
  void expires_never();

 private:
  mutable std::mutex mutex_;

  next_layer_type socket_;
  IObfuscatorSPtr obfuscator_;

  strand_type strand_;

  std::unique_ptr<boost::asio::steady_timer> timer_;
};

// External functions for working with Socket
void teardown(boost::beast::role_type role,
    Socket& socket,
    boost::system::error_code& ec);

template <typename TeardownHandler>
void async_teardown(
    boost::beast::role_type role, Socket& socket, TeardownHandler&& handler) {
  boost::system::error_code ec;
  teardown(role, socket, ec);
  std::forward<TeardownHandler>(handler)(ec);
}

using SocketSPtr = std::shared_ptr<Socket>;

}  // namespace fptn::protocol::https::obfuscator
