/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/obfuscator/socket/socket.h"

#include <future>

#include <boost/beast.hpp>
#include <boost/system/error_code.hpp>

namespace fptn::protocol::https::obfuscator {

Socket::Socket(const executor_type& ex) : socket_(ex), strand_(ex) {}

Socket::Socket(const executor_type& ex, IObfuscatorSPtr obfuscator)
    : socket_(ex), obfuscator_(std::move(obfuscator)), strand_(ex) {}

Socket::Socket(next_layer_type&& socket)
    : socket_(std::move(socket)), strand_(socket_.get_executor()) {}

Socket::Socket(next_layer_type&& socket, IObfuscatorSPtr obfuscator)
    : socket_(std::move(socket)),
      obfuscator_(std::move(obfuscator)),
      strand_(socket_.get_executor()) {}

void Socket::SetObfuscator(IObfuscatorSPtr obfuscator) {
  auto self = shared_from_this();
  boost::asio::post(
      strand_, [self, obfuscator = std::move(obfuscator)]() mutable {
        self->obfuscator_ = std::move(obfuscator);
      });
}

Socket::next_layer_type& Socket::next_layer() { return socket_; }
const Socket::next_layer_type& Socket::next_layer() const { return socket_; }

Socket::lowest_layer_type& Socket::lowest_layer() { return socket_; }
const Socket::lowest_layer_type& Socket::lowest_layer() const {
  return socket_;
}

Socket::executor_type Socket::get_executor() { return socket_.get_executor(); }

void Socket::close(boost::system::error_code& ec) {
  std::promise<void> promise;
  auto future = promise.get_future();

  auto self = shared_from_this();
  boost::asio::post(strand_, [self, &promise, &ec]() {
    if (self->obfuscator_) {
      self->obfuscator_->Reset();
    }
    self->socket_.close(ec);
    promise.set_value();
  });

  future.wait();
}

void Socket::close() {
  auto self = shared_from_this();
  boost::asio::post(strand_, [self]() {
    if (self->obfuscator_) {
      self->obfuscator_->Reset();
    }
    self->socket_.close();
  });
}

bool Socket::is_open() const { return socket_.is_open(); }

Socket::endpoint_type Socket::remote_endpoint(
    boost::system::error_code& ec) const {
  return socket_.remote_endpoint(ec);
}

Socket::endpoint_type Socket::local_endpoint(
    boost::system::error_code& ec) const {
  return socket_.local_endpoint(ec);
}

void Socket::expires_after(std::chrono::steady_clock::duration timeout) {
  auto self = shared_from_this();
  boost::asio::post(strand_, [self, timeout]() {
    const auto timeout_sec =
        std::chrono::duration_cast<std::chrono::seconds>(timeout);

    auto native_handle = self->socket_.native_handle();

    struct timeval tv = {};
    tv.tv_sec = timeout_sec.count();
    tv.tv_usec = 0;
    ::setsockopt(native_handle, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(native_handle, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  });
}

void Socket::expires_never() {
  auto self = shared_from_this();
  boost::asio::post(strand_, [self]() {
    auto native_handle = self->socket_.native_handle();

    struct timeval tv = {};
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    ::setsockopt(native_handle, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(native_handle, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  });
}

void teardown(boost::beast::role_type role,
    Socket& socket,
    boost::system::error_code& ec) {
  (void)role;

  std::promise<void> promise;
  auto future = promise.get_future();

  boost::asio::post(socket.get_strand(), [&socket, &promise, &ec]() {
    socket.lowest_layer().shutdown(
        boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket.close(ec);
    promise.set_value();
  });

  future.wait();
}

}  // namespace fptn::protocol::https::obfuscator
