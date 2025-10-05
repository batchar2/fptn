/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>

#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/obfuscator/methods/none/none_obfuscator.h"

namespace fptn::protocol::https {

WebsocketClient::WebsocketClient(pcpp::IPv4Address server_ip,
    int server_port,
    pcpp::IPv4Address tun_interface_address_ipv4,
    pcpp::IPv6Address tun_interface_address_ipv6,
    NewIPPacketCallback new_ip_pkt_callback,
    std::string sni,
    std::string access_token,
    std::string expected_md5_fingerprint,
    obfuscator::IObfuscatorSPtr obfuscator,
    OnConnectedCallback on_connected_callback)
    : ctx_(fptn::protocol::https::utils::CreateNewSslCtx()),
      resolver_(boost::asio::make_strand(ioc_)),
      obfuscator_(std::move(obfuscator)),
      socket_(std::make_shared<obfuscator::Socket>(
          ioc_.get_executor(), obfuscator_)),
      socket_wrapper_(std::make_shared<obfuscator::SocketWrapper>(socket_)),
      ssl_stream_(std::make_unique<ssl_socket_stream>(*socket_wrapper_, ctx_)),
      ws_(*ssl_stream_),
      strand_(ioc_.get_executor()),
      write_channel_(strand_, kMaxSizeOutQueue_),
      server_ip_(std::move(server_ip)),
      server_port_str_(std::to_string(server_port)),
      tun_interface_address_ipv4_(std::move(tun_interface_address_ipv4)),
      tun_interface_address_ipv6_(std::move(tun_interface_address_ipv6)),
      new_ip_pkt_callback_(std::move(new_ip_pkt_callback)),
      sni_(std::move(sni)),
      access_token_(std::move(access_token)),
      expected_md5_fingerprint_(std::move(expected_md5_fingerprint)),
      on_connected_callback_(std::move(on_connected_callback)) {
  auto* ssl = ws_.next_layer().native_handle();
  fptn::protocol::https::utils::SetHandshakeSni(ssl, sni_);
  fptn::protocol::https::utils::SetHandshakeSessionID(ssl);

  ssl_ = ws_.next_layer().native_handle();
  fptn::protocol::https::utils::AttachCertificateVerificationCallback(
      ssl_, [this](const std::string& md5_fingerprint) mutable {
        if (md5_fingerprint == expected_md5_fingerprint_) {
          SPDLOG_INFO("Certificate verified successfully (MD5 matched: {}).",
              md5_fingerprint);
          return true;
        }
        SPDLOG_ERROR(
            "Certificate MD5 mismatch. Expected: {}, got: {}. "
            "Please update your token.",
            expected_md5_fingerprint_, md5_fingerprint);
        return false;
      });

  // Configure WebSocket
  ws_.text(false);
  ws_.binary(true);
  ws_.auto_fragment(true);
  ws_.read_message_max(128 * 1024);
  ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
      boost::beast::role_type::client));
}

WebsocketClient::~WebsocketClient() {
  Stop();
  if (ssl_) {
    protocol::https::utils::AttachCertificateVerificationCallbackDelete(ssl_);
    ssl_ = nullptr;
  }
}

void WebsocketClient::Run() {
  try {
    running_ = true;
    SPDLOG_INFO("Connection: {}:{}", server_ip_.toString(), server_port_str_);

    obfuscator_->Reset();

    // Start the main client coroutine on strand
    boost::asio::co_spawn(
        strand_,
        [self = shared_from_this()]() -> boost::asio::awaitable<void> {
          return self->RunClient();
        },
        boost::asio::detached);

    ioc_.run();
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Error run ws: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined ws error");
  }
}

bool WebsocketClient::Stop() {
  if (!running_) {
    return false;
  }

  if (!running_.exchange(false)) {
    return false;
  }

  SPDLOG_INFO("Marked client as stopped and disconnected");

  was_connected_ = false;

  // Cancel all ongoing operations
  cancel_signal_.emit(boost::asio::cancellation_type::all);
  write_channel_.close();

  boost::system::error_code ec;

  // Close WebSocket
  try {
    if (ws_.is_open()) {
      ws_.close(boost::beast::websocket::close_code::normal, ec);
      if (ec) {
        SPDLOG_WARN("WebSocket close error: {}", ec.message());
      }
    }
  } catch (const std::exception& err) {
    SPDLOG_ERROR("Failed to close WebSocket: {}", err.what());
  }

  // Close SSL
  try {
    auto& ssl = ws_.next_layer();
    if (ssl.native_handle()) {
      ::SSL_set_quiet_shutdown(ssl.native_handle(), 1);
      ::SSL_shutdown(ssl.native_handle());
    }
    ssl.shutdown(ec);
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during SSL shutdown: {}", err.what());
  }

  // Close TCP connection
  try {
    socket_->close(ec);
    if (ec) {
      SPDLOG_WARN("TCP socket close error: {}", ec.message());
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during TCP shutdown: {}", err.what());
  }

  // Stop io_context
  try {
    ioc_.stop();
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception while stopping io_context: {}", err.what());
  }

  SPDLOG_INFO("WebSocket client stopped successfully");
  return true;
}

boost::asio::awaitable<void> WebsocketClient::RunClient() {
  boost::system::error_code ec;

  try {
    // Resolve endpoint
    auto results = co_await resolver_.async_resolve(server_ip_.toString(),
        server_port_str_,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (ec) {
      SPDLOG_ERROR("Resolve error: {}", ec.message());
      co_return;
    }

    // Connect using the underlying TCP socket
    socket_->expires_after(std::chrono::seconds(30));
    co_await socket_->next_layer().async_connect(*results.begin(),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (ec) {
      SPDLOG_ERROR("Connect error: {}", ec.message());
      co_return;
    }

    // SSL handshake
    socket_->expires_after(std::chrono::seconds(30));
    co_await ws_.next_layer().async_handshake(
        boost::asio::ssl::stream_base::client,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (ec) {
      SPDLOG_ERROR("SSL handshake error: {}", ec.message());
      co_return;
    }

    // WebSocket handshake
    socket_->expires_after(std::chrono::hours(24));

    ws_.set_option(boost::beast::websocket::stream_base::decorator(
        [self = shared_from_this()](
            boost::beast::websocket::request_type& req) {
          const auto headers =
              fptn::protocol::https::RealBrowserHeaders(self->sni_);
          for (const auto& [key, value] : headers) {
            req.set(key, value);
          }
          req.set("Authorization", "Bearer " + self->access_token_);
          req.set("ClientIP", self->tun_interface_address_ipv4_.toString());
          req.set("ClientIPv6", self->tun_interface_address_ipv6_.toString());
          req.set("Client-Agent",
              fmt::format("FptnClient({}/{})", FPTN_USER_OS, FPTN_VERSION));
        }));

    co_await ws_.async_handshake(server_ip_.toString(), kUrlWebSocket_,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (ec) {
      SPDLOG_ERROR("WebSocket handshake error: {}", ec.message());
      co_return;
    }

    was_connected_ = true;
    SPDLOG_INFO("WebSocket connection started successfully");

    // Set timeout options
    boost::beast::websocket::stream_base::timeout timeout_option;
    timeout_option.handshake_timeout = std::chrono::seconds(10);
    timeout_option.idle_timeout =
        std::chrono::seconds(30);  // Увеличиваем таймаут
    timeout_option.keep_alive_pings = true;
    ws_.set_option(timeout_option);

    if (on_connected_callback_) {
      on_connected_callback_();
    }

    boost::asio::co_spawn(
        strand_,
        [self = shared_from_this()]() -> boost::asio::awaitable<void> {
          return self->RunReader();
        },
        boost::asio::detached);

    boost::asio::co_spawn(
        strand_,
        [self = shared_from_this()]() -> boost::asio::awaitable<void> {
          return self->RunSender();
        },
        boost::asio::detached);

  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception in RunClient: {}", e.what());
    Stop();
  }
  co_return;
}

boost::asio::awaitable<void> WebsocketClient::RunReader() {
  boost::system::error_code ec;

  auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);
  (void)token;
  boost::beast::flat_buffer buffer;

  SPDLOG_INFO("RunReader started");

  try {
    while (running_) {
      if (!ws_.is_open()) {
        SPDLOG_WARN("WebSocket is not open in RunReader");
        break;
      }

      co_await boost::asio::post(strand_, boost::asio::use_awaitable);

      co_await ws_.async_read(buffer,
          boost::asio::bind_executor(strand_,
              boost::asio::redirect_error(boost::asio::use_awaitable, ec)));

      // co_await ws_.async_read(buffer, token);
      if (ec) {
        SPDLOG_ERROR(
            "RunReader: Read error: {} [code: {}]", ec.message(), ec.value());
        break;
      }

      if (buffer.size() > 0) {
        std::string data = boost::beast::buffers_to_string(buffer.data());
        std::string raw = protobuf::GetProtoPayload(std::move(data));
        auto packet = fptn::common::network::IPPacket::Parse(std::move(raw));

        if (running_ && packet) {
          new_ip_pkt_callback_(std::move(packet));
        }
        buffer.consume(buffer.size());
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunReader: Exception: {}", e.what());
  }

  SPDLOG_INFO("RunReader exiting");
  if (running_) {
    Stop();
  }
  co_return;
}

boost::asio::awaitable<void> WebsocketClient::RunSender() {
  boost::system::error_code ec;

  auto token = boost::asio::bind_cancellation_slot(cancel_signal_.slot(),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));

  SPDLOG_INFO("RunSender started");

  try {
    while (running_) {
      if (!ws_.is_open()) {
        SPDLOG_WARN("WebSocket is not open in RunSender");
        break;
      }

      auto packet = co_await write_channel_.async_receive(
          boost::asio::bind_cancellation_slot(cancel_signal_.slot(),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec)));

      if (ec) {
        if (ec == boost::asio::error::operation_aborted) {
          SPDLOG_DEBUG("RunSender channel operation aborted (normal shutdown)");
        } else {
          SPDLOG_ERROR("RunSender: Channel receive error: {}", ec.message());
        }
        break;
      }

      if (packet) {
        std::string msg = protobuf::CreateProtoPayload(std::move(packet));

        co_await boost::asio::post(strand_, boost::asio::use_awaitable);

        co_await ws_.async_write(boost::asio::buffer(msg.data(), msg.size()),
            boost::asio::bind_executor(strand_,
                boost::asio::redirect_error(boost::asio::use_awaitable, ec)));

        // co_await ws_.async_write(
        //     boost::asio::buffer(msg.data(), msg.size()), token);

        // co_await ws_.async_write(boost::asio::buffer(msg.data(), msg.size()),
        //     boost::asio::bind_cancellation_slot(cancel_signal_.slot(),
        //         boost::asio::redirect_error(boost::asio::use_awaitable,
        //         ec)));

        if (ec) {
          SPDLOG_ERROR("RunSender: Write error: {} [code: {}]", ec.message(),
              ec.value());

          break;
        }
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunSender: Exception: {}", e.what());
  }

  SPDLOG_INFO("RunSender exiting");
  if (running_) {
    Stop();
  }
  co_return;
}

bool WebsocketClient::Send(fptn::common::network::IPPacketPtr packet) {
  if (!running_ || !was_connected_) {
    return false;
  }

  boost::asio::post(strand_,
      [self = shared_from_this(), packet = std::move(packet)]() mutable {
        if (!self->write_channel_.try_send(
                boost::system::error_code(), std::move(packet))) {
          SPDLOG_WARN("Send queue is full");
        }
      });

  return true;
}

void WebsocketClient::Fail(boost::system::error_code ec, char const* what) {
  if (running_) {
    SPDLOG_ERROR("Fail {}: {} [code: {}]", what, ec.message(), ec.value());
  }
  Stop();
}

bool WebsocketClient::IsStarted() { return running_ && was_connected_; }

}  // namespace fptn::protocol::https
