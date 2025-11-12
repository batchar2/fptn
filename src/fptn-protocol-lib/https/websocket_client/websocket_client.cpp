/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/api_client/api_client.h"

namespace fptn::protocol::https {

WebsocketClient::WebsocketClient(fptn::common::network::IPv4Address server_ip,
    int server_port,
    fptn::common::network::IPv4Address tun_interface_address_ipv4,
    fptn::common::network::IPv6Address tun_interface_address_ipv6,
    NewIPPacketCallback new_ip_pkt_callback,
    std::string sni,
    std::string access_token,
    std::string expected_md5_fingerprint,
    obfuscator::IObfuscatorSPtr obfuscator,
    OnConnectedCallback on_connected_callback)
    : ctx_(https::utils::CreateNewSslCtx()),
      resolver_(boost::asio::make_strand(ioc_)),
      obfuscator_(std::move(obfuscator)),
      ws_(ssl_stream_type(
          obfuscator_socket_type(boost::asio::make_strand(ioc_), obfuscator_),
          ctx_)),
      strand_(boost::asio::make_strand(ioc_)),
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
  https::utils::SetHandshakeSni(ssl, sni_);
  https::utils::SetHandshakeSessionID(ssl);

  https::utils::AttachCertificateVerificationCallback(
      ssl, [this](const std::string& md5_fingerprint) mutable {
        if (!expected_md5_fingerprint_.empty()) {
          return true;
        }
        if (md5_fingerprint == expected_md5_fingerprint_) {
          SPDLOG_INFO("Certificate verified successfully (MD5 matched: {}).",
              md5_fingerprint);
          return true;
        }
        SPDLOG_ERROR("Certificate MD5 mismatch. Expected: {}, got: {}.",
            expected_md5_fingerprint_, md5_fingerprint);
        return false;
      });

  ws_.text(false);
  ws_.binary(true);
  ws_.auto_fragment(true);
  ws_.read_message_max(128 * 1024);
  ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
      boost::beast::role_type::client));
}

WebsocketClient::~WebsocketClient() {
  Stop();
  if (auto* ssl = ws_.next_layer().native_handle()) {
    https::utils::AttachCertificateVerificationCallbackDelete(ssl);
  }
}

void WebsocketClient::Run() {
  if (running_.exchange(true)) {
    SPDLOG_WARN("WebsocketClient is already running");
    return;
  }

  SPDLOG_INFO("Connecting to {}:{}", server_ip_.ToString(), server_port_str_);

  if (obfuscator_) {
    obfuscator_->Reset();
  }

  boost::asio::co_spawn(
      ioc_,
      [self = shared_from_this()]() -> boost::asio::awaitable<void> {
        const bool status = co_await self->RunInternal();
        if (!status) {
          self->Stop();
        }
      },
      boost::asio::detached);
  ioc_.run();
}

bool WebsocketClient::Stop() {
  try {
    if (!running_) {
      return false;
    }

    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      // cppcheck-suppress identicalConditionAfterEarlyExit
      if (!running_) {  // Double-check after acquiring lock
        return false;
      }
      running_ = false;
      was_connected_ = false;
    }

    auto stop_promise = std::make_shared<std::promise<void>>();
    auto stop_future = stop_promise->get_future();

    auto self = shared_from_this();
    boost::asio::post(strand_, [self, stop_promise]() noexcept {
      try {
        boost::system::error_code ec;

        // Send signal
        self->cancel_signal_.emit(boost::asio::cancellation_type::all);

        // Close WebSocket
        if (self->ws_.is_open()) {
          self->ws_.close(boost::beast::websocket::close_code::normal, ec);
        }

        // Close SSL
        try {
          SPDLOG_DEBUG("Shutting down SSL layer...");
          auto& ssl = self->ws_.next_layer();
          if (ssl.native_handle()) {
            ::SSL_set_quiet_shutdown(ssl.native_handle(), 1);
            ::SSL_shutdown(ssl.native_handle());
          }
          ssl.shutdown(ec);
        } catch (const boost::system::system_error& err) {
          SPDLOG_ERROR("Exception during SSL shutdown: {}", err.what());
        } catch (const std::exception& e) {
          SPDLOG_ERROR(
              "Unexpected exception during SSL shutdown: {}", e.what());
        } catch (...) {
          SPDLOG_ERROR("Unknown exception occurred during SSL shutdown");
        }

        // Close TCP
        try {
          auto& tcp = boost::beast::get_lowest_layer(self->ws_);
          if (tcp.socket().is_open()) {
            tcp.socket().shutdown(
                boost::asio::ip::tcp::socket::shutdown_both, ec);
            try {
              tcp.close();
            } catch (const std::exception& e) {
              SPDLOG_ERROR("Exception during TCP shutdown: {}", e.what());
            }
          }
        } catch (const boost::system::system_error& err) {
          SPDLOG_ERROR("Exception during TCP shutdown: {}", err.what());
        } catch (...) {
          SPDLOG_ERROR("Unknown exception during TCP shutdown");
        }
        SPDLOG_INFO("WebsocketClient shutdown completed");
      } catch (...) {
        SPDLOG_ERROR("Unexpected exception during shutdown");
      }
      stop_promise->set_value();
    });

    if (stop_future.wait_for(std::chrono::seconds(5)) ==
        std::future_status::timeout) {
      SPDLOG_WARN("WebsocketClient stop timeout, forcing shutdown");
    }

    // Stop io_context
    try {
      SPDLOG_DEBUG("Stopping io_context...");
      ioc_.stop();
      SPDLOG_DEBUG("io_context stopped");
    } catch (const boost::system::system_error& err) {
      SPDLOG_ERROR("Exception while stopping io_context: {}", err.what());
    } catch (...) {
      SPDLOG_ERROR("Unknown exception while stopping io_context");
    }

    SPDLOG_INFO("WebsocketClient fully stopped");

    return true;
  } catch (const std::exception& e) {
    SPDLOG_CRITICAL("Exception in Stop(): {}", e.what());
  } catch (...) {
    SPDLOG_CRITICAL("Unknown exception in Stop()");
  }
  return false;
}

bool WebsocketClient::Send(fptn::common::network::IPPacketPtr packet) {
  if (!running_ || !was_connected_) {
    return false;
  }
  try {
    return write_channel_.try_send(
        boost::system::error_code(), std::move(packet));
  } catch (...) {
    return false;
  }
}

bool WebsocketClient::IsStarted() const { return running_ && was_connected_; }

boost::asio::awaitable<bool> WebsocketClient::RunInternal() {
  try {
    const bool connected = co_await Connect();
    if (!connected) {
      running_ = false;
      co_return false;
    }

    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(6));

    // Start reader and sender
    auto self = shared_from_this();
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunReader(); }, boost::asio::detached);
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunSender(); }, boost::asio::detached);
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunInternal exception: {}", e.what());
    running_ = false;
  }
  co_return false;
}

boost::asio::awaitable<bool> WebsocketClient::Connect() {
  boost::system::error_code ec;
  try {
    // DNS resolution
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
    auto results = co_await resolver_.async_resolve(server_ip_.ToString(),
        server_port_str_,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Resolve error: {}", ec.message());
      co_return false;
    }

    // TCP connect
    co_await boost::beast::get_lowest_layer(ws_).async_connect(
        results, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Connect error: {}", ec.message());
      co_return false;
    }

    SPDLOG_INFO("Connected to {}:{}", server_ip_.ToString(), server_port_str_);

    // TCP options
    boost::beast::get_lowest_layer(ws_).socket().set_option(
        boost::asio::ip::tcp::no_delay(true));

    // Set obfuscator
    if (obfuscator_ != nullptr) {
      ws_.next_layer().next_layer().set_obfuscator(obfuscator_);
    }

    // SSL handshake
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(10));
    co_await ws_.next_layer().async_handshake(
        boost::asio::ssl::stream_base::client,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("SSL handshake error: {}", ec.message());
      co_return false;
    }

    // Reset obfuscator after TLS-handshake
    if (obfuscator_ != nullptr) {
      constexpr int kMaxRetries = 10;
      int retry_count = 0;
      do {
        co_await boost::asio::steady_timer(
            co_await boost::asio::this_coro::executor,
            std::chrono::milliseconds(200))
            .async_wait(boost::asio::use_awaitable);
        retry_count += 1;
      } while (obfuscator_->HasPendingData() && retry_count < kMaxRetries);
      if (retry_count >= kMaxRetries) {
        SPDLOG_WARN(
            "Failed to clear obfuscator pending data within {} attempts. ",
            retry_count);
        co_return false;
      }
      ws_.next_layer().next_layer().set_obfuscator(nullptr);
    }
    SPDLOG_INFO("SSL handshake completed");

    // WebSocket options
    boost::beast::websocket::stream_base::timeout timeout_option;
    timeout_option.handshake_timeout = std::chrono::seconds(10);
    timeout_option.idle_timeout = std::chrono::seconds(30);
    timeout_option.keep_alive_pings = true;
    ws_.set_option(timeout_option);

    // WebSocket handshake
    ws_.set_option(boost::beast::websocket::stream_base::decorator(
        [this](boost::beast::websocket::request_type& req) {
          req.set("Authorization", "Bearer " + access_token_);
          req.set("ClientIP", tun_interface_address_ipv4_.ToString());
          req.set("ClientIPv6", tun_interface_address_ipv6_.ToString());
          req.set("Client-Agent",
              fmt::format("FptnClient({}/{})", FPTN_USER_OS, FPTN_VERSION));
        }));
    co_await ws_.async_handshake(server_ip_.ToString(), kUrlWebSocket_,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("WebSocket handshake error: {}", ec.message());
      co_return false;
    }

    was_connected_ = true;
    SPDLOG_INFO("WebSocket connection established successfully");

    if (on_connected_callback_) {
      on_connected_callback_();
    }
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Connect exception: {}", e.what());
  }
  co_return false;
}

boost::asio::awaitable<void> WebsocketClient::RunReader() {
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;

  try {
    while (running_ && was_connected_ && ws_.is_open()) {
      co_await ws_.async_read(
          buffer, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

      if (ec) {
        if (ec != boost::beast::websocket::error::closed) {
          SPDLOG_DEBUG("WebSocket read error: {}", ec.message());
        }
        break;
      }

      if (buffer.size() > 0) {
        std::string data = boost::beast::buffers_to_string(buffer.data());
        std::string raw = protobuf::GetProtoPayload(std::move(data));
        auto packet = fptn::common::network::IPPacket::Parse(std::move(raw));

        if (running_ && packet && new_ip_pkt_callback_) {
          new_ip_pkt_callback_(std::move(packet));
        }
      }
      buffer.consume(buffer.size());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunReader exception: {}", e.what());
  }

  Stop();
  co_return;
}

boost::asio::awaitable<void> WebsocketClient::RunSender() {
  try {
    while (running_ && was_connected_ && ws_.is_open()) {
      auto [ec, packet] = co_await write_channel_.async_receive(
          boost::asio::bind_cancellation_slot(cancel_signal_.slot(),
              boost::asio::as_tuple(boost::asio::use_awaitable)));

      if (packet != nullptr && running_ && ws_.is_open() && !ec) {
        std::string msg =
            fptn::protocol::protobuf::CreateProtoPayload(std::move(packet));
        if (!msg.empty()) {
          co_await ws_.async_write(boost::asio::buffer(msg),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            SPDLOG_ERROR("WebSocket write error: {}", ec.message());
            break;
          }
        }
      } else if (ec) {
        break;
      }
    }
  } catch (const boost::system::system_error& err) {
    if (err.code() != boost::asio::error::operation_aborted) {
      SPDLOG_ERROR("RunSender error: {}", err.what());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunSender exception: {}", e.what());
  }

  Stop();
  co_return;
}

}  // namespace fptn::protocol::https
