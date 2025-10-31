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
#include <boost/asio/strand.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <openssl/ssl.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::protocol::https::obfuscator {

template <typename Stream>
class TcpStream {
 public:
  using executor_type = typename Stream::executor_type;
  using next_layer_type = Stream;
  using lowest_layer_type = Stream;

  TcpStream(executor_type ex, IObfuscatorSPtr obfuscator)
      : stream_(ex), obfuscator_(std::move(obfuscator)) {}

  TcpStream(Stream&& stream, IObfuscatorSPtr obfuscator)
      : stream_(std::move(stream)), obfuscator_(std::move(obfuscator)) {}

  TcpStream(const TcpStream&) = delete;
  TcpStream& operator=(const TcpStream&) = delete;

  TcpStream(TcpStream&& other) noexcept
      : stream_(std::move(other.stream_)),
        obfuscator_(std::move(other.obfuscator_)) {}

  TcpStream& operator=(TcpStream&& other) noexcept {
    if (this != &other) {
      stream_ = std::move(other.stream_);
      obfuscator_ = std::move(other.obfuscator_);
    }
    return *this;
  }

  executor_type get_executor() { return stream_.get_executor(); }

  next_layer_type& next_layer() { return stream_; }

  const next_layer_type& next_layer() const { return stream_; }

  lowest_layer_type& lowest_layer() { return stream_; }

  const lowest_layer_type& lowest_layer() const { return stream_; }

  template <typename MutableBufferSequence>
  std::size_t read_some(
      const MutableBufferSequence& buffers, boost::system::error_code& ec) {
    const auto size = stream_.read_some(buffers, ec);
    return size;
  }

  template <typename MutableBufferSequence, typename ReadHandler>
  void async_read_some(
      const MutableBufferSequence& buffers, ReadHandler&& handler) {
    stream_.async_read_some(
        buffers, [handler = std::forward<ReadHandler>(handler)](
                     boost::system::error_code ec, std::size_t size) mutable {
          handler(ec, size);
        });
  }

  template <typename ConstBufferSequence>
  std::size_t write_some(
      const ConstBufferSequence& buffers, boost::system::error_code& ec) {
    const auto size = stream_.write_some(buffers, ec);
    return size;
  }

  template <typename ConstBufferSequence, typename WriteHandler>
  void async_write_some(
      const ConstBufferSequence& buffers, WriteHandler&& handler) {
    stream_.async_write_some(
        buffers, [handler = std::move(handler)](boost::system::error_code ec,
                     std::size_t size) mutable { handler(ec, size); });
  }

  template <typename... Args>
  auto async_connect(Args&&... args) {
    return stream_.async_connect(std::forward<Args>(args)...);
  }

  void close() { stream_.close(); }

  void close(boost::system::error_code& ec) { stream_.close(ec); }

  template <typename Option>
  void set_option(const Option& option) {
    stream_.set_option(option);
  }

  void expires_after(std::chrono::steady_clock::duration expiry_time) {
    stream_.expires_after(expiry_time);
  }

  void expires_never() { stream_.expires_never(); }

  bool is_open() const { return stream_.is_open(); }

  auto remote_endpoint() { return stream_.socket().remote_endpoint(); }
  auto remote_endpoint(boost::system::error_code& ec) {
    return stream_.socket().remote_endpoint(ec);
  }

  auto local_endpoint() { return stream_.socket().local_endpoint(); }
  auto local_endpoint(boost::system::error_code& ec) {
    return stream_.socket().local_endpoint(ec);
  }

 private:
  Stream stream_;
  IObfuscatorSPtr obfuscator_;
};

}  // namespace fptn::protocol::https::obfuscator

namespace boost::beast {

template <typename AsyncStream>
inline void teardown(boost::beast::role_type role,
    fptn::protocol::https::obfuscator::TcpStream<AsyncStream>& stream,
    boost::system::error_code& ec) {
  teardown(role, stream.next_layer(), ec);
}

template <typename AsyncStream, typename TeardownHandler>
inline void async_teardown(boost::beast::role_type role,
    fptn::protocol::https::obfuscator::TcpStream<AsyncStream>& stream,
    TeardownHandler&& handler) {
  async_teardown(
      role, stream.next_layer(), std::forward<TeardownHandler>(handler));
}

}  // namespace boost::beast
