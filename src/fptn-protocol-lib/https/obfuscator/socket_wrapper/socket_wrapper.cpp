/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/obfuscator/socket_wrapper/socket_wrapper.h"

namespace fptn::protocol::https::obfuscator {

SocketWrapper::SocketWrapper(SocketSPtr socket) : socket_(std::move(socket)) {}

SocketWrapper::next_layer_type& SocketWrapper::next_layer() { return *socket_; }
const SocketWrapper::next_layer_type& SocketWrapper::next_layer() const {
  return *socket_;
}

SocketWrapper::lowest_layer_type& SocketWrapper::lowest_layer() {
  return socket_->lowest_layer();
}
const SocketWrapper::lowest_layer_type& SocketWrapper::lowest_layer() const {
  return socket_->lowest_layer();
}

SocketWrapper::executor_type SocketWrapper::get_executor() {
  return socket_->get_executor();
}

void SocketWrapper::close(boost::system::error_code& ec) { socket_->close(ec); }
void SocketWrapper::close() { socket_->close(); }
bool SocketWrapper::is_open() const { return socket_->is_open(); }

SocketWrapper::endpoint_type SocketWrapper::remote_endpoint(
    boost::system::error_code& ec) const {
  return socket_->remote_endpoint(ec);
}

SocketWrapper::endpoint_type SocketWrapper::local_endpoint(
    boost::system::error_code& ec) const {
  return socket_->local_endpoint(ec);
}

template <typename Option>
void SocketWrapper::set_option(const Option& option) {
  socket_->set_option(option);
}

void SocketWrapper::expires_after(std::chrono::steady_clock::duration timeout) {
  socket_->expires_after(timeout);
}

void SocketWrapper::expires_never() { socket_->expires_never(); }

void teardown(boost::beast::role_type role,
    SocketWrapper& socket,
    boost::system::error_code& ec) {
  teardown(role, socket.next_layer(), ec);
}

}  // namespace fptn::protocol::https::obfuscator
