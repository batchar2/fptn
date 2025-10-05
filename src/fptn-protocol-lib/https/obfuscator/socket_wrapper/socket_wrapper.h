/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>

#include <boost/beast.hpp>
#include <boost/system/error_code.hpp>

#include "fptn-protocol-lib/https/obfuscator/socket/socket.h"

namespace fptn::protocol::https::obfuscator {

class SocketWrapper {
 public:
  using next_layer_type = Socket;
  using lowest_layer_type = Socket::lowest_layer_type;
  using executor_type = Socket::executor_type;
  using endpoint_type = Socket::endpoint_type;

  explicit SocketWrapper(SocketSPtr socket);

  next_layer_type& next_layer();
  const next_layer_type& next_layer() const;

  lowest_layer_type& lowest_layer();
  const lowest_layer_type& lowest_layer() const;

  executor_type get_executor();

  template <typename MutableBufferSequence>
  std::size_t read_some(
      const MutableBufferSequence& buffers, boost::system::error_code& ec) {
    return socket_->read_some(buffers, ec);
  }

  template <typename ConstBufferSequence>
  std::size_t write_some(
      const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    return socket_->write_some(buffers, ec);
  }

  // template <typename MutableBufferSequence, typename ReadHandler>
  // void async_read_some(
  //     const MutableBufferSequence& buffers, ReadHandler&& handler) {
  //   socket_->async_read_some(
  //       buffers, boost::asio::bind_executor(socket_->get_strand(),
  //                    std::forward<ReadHandler>(handler)));
  // }

  // template <typename MutableBufferSequence, typename ReadHandler>
  // void async_read_some(
  //     const MutableBufferSequence& buffers, ReadHandler&& handler) {
  //   socket_->async_read_some(buffers, std::forward<ReadHandler>(handler));
  // }

  template <typename MutableBufferSequence, typename ReadHandler>
  void async_read_some(
      const MutableBufferSequence& buffers, ReadHandler&& handler) {
    socket_->async_read_some(
        buffers, boost::asio::bind_executor(socket_->get_strand(),
                     std::forward<ReadHandler>(handler)));
  }

  template <typename ConstBufferSequence, typename WriteHandler>
  void async_write_some(
      const ConstBufferSequence& buffers, WriteHandler&& handler) {
    socket_->async_write_some(buffers, std::forward<WriteHandler>(handler));
  }

  template <typename ConnectHandler>
  void async_connect(
      const endpoint_type& peer_endpoint, ConnectHandler&& handler) {
    socket_->async_connect(
        peer_endpoint, std::forward<ConnectHandler>(handler));
  }

  void close(boost::system::error_code& ec);
  void close();
  bool is_open() const;

  endpoint_type remote_endpoint(boost::system::error_code& ec) const;
  endpoint_type local_endpoint(boost::system::error_code& ec) const;

  template <typename Option>
  void set_option(const Option& option);

  void expires_after(std::chrono::steady_clock::duration timeout);
  void expires_never();

 private:
  SocketSPtr socket_;
};

void teardown(boost::beast::role_type role,
    SocketWrapper& socket,
    boost::system::error_code& ec);

template <typename TeardownHandler>
void async_teardown(boost::beast::role_type role,
    SocketWrapper& socket,
    TeardownHandler&& handler) {
  async_teardown(
      role, socket.next_layer(), std::forward<TeardownHandler>(handler));
}

using SocketWrapperSPtr = std::shared_ptr<SocketWrapper>;

}  // namespace fptn::protocol::https::obfuscator
