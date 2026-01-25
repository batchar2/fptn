/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"

namespace fptn::protocol::https {

WebsocketClient::WebsocketClient(
    std::string jwt_access_token, ConnectionConfig config, int thread_number)
    : ioc_(thread_number),
      ctx_(https::utils::CreateNewSslCtx()),
      resolver_(boost::asio::make_strand(ioc_)),
      ws_(ssl_stream_type(
          obfuscator_socket_type(boost::asio::make_strand(ioc_), nullptr),
          ctx_)),
      strand_(boost::asio::make_strand(ioc_)),
      watchdog_timer_(strand_),
      write_channel_(strand_, kMaxSizeOutQueue_),

      jwt_access_token_(std::move(jwt_access_token)),
      config_(std::move(config)) {
  auto* ssl = ws_.next_layer().native_handle();
  https::utils::SetHandshakeSni(ssl, config_.common.sni);
  https::utils::SetHandshakeSessionID(ssl);

  if (config_.common.https_init_connection_strategy ==
      HttpsInitConnectionStrategy::kSni) {
    obfuscator_ = nullptr;
  }
  if (config_.common.https_init_connection_strategy ==
      HttpsInitConnectionStrategy::kTlsObfuscator) {
    obfuscator_ =
        std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator>();
    ws_.next_layer().next_layer().set_obfuscator(obfuscator_);
  }

  if (config_.common.https_init_connection_strategy ==
      HttpsInitConnectionStrategy::kSniRealityMode) {
    obfuscator_ = nullptr;
  }

  https::utils::AttachCertificateVerificationCallback(
      ssl, [this](const std::string& md5_fingerprint) mutable {
        if (config_.common.md5_fingerprint.empty()) {
          return true;
        }
        if (md5_fingerprint == config_.common.md5_fingerprint) {
          return true;
        }
        SPDLOG_ERROR("Certificate MD5 mismatch. Expected: {}, got: {}.",
            config_.common.md5_fingerprint, md5_fingerprint);
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
  try {
    Stop();
  } catch (...) {
    SPDLOG_WARN("Unknown error in ~WebsocketClient");
  }

  // Stop io_context
  try {
    if (!ioc_.stopped()) {
      SPDLOG_INFO("Stopping io_context...");
      ioc_.stop();
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception while stopping io_context: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while stopping io_context");
  }
  SPDLOG_INFO("WebsocketClient removed");
}

void WebsocketClient::Run() {
  if (running_.exchange(true)) {
    SPDLOG_WARN("WebsocketClient is already running");
    return;
  }

  SPDLOG_INFO("Connecting to {}:{}", config_.common.server_ip.ToString(),
      config_.common.server_port);

  auto self = weak_from_this();
  boost::asio::co_spawn(
      ioc_,
      [self]() -> boost::asio::awaitable<void> {
        if (auto shared_self = self.lock()) {
          const bool status = co_await shared_self->RunInternal();
          if (!status) {
            shared_self->Stop();
          }
        }
      },
      boost::asio::detached);
  try {
    while (running_ || !was_stopped_) {
      const std::size_t processed = ioc_.poll_one();
      if (processed == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }
    if (!ioc_.stopped()) {
      ioc_.stop();
    }
  } catch (...) {
    SPDLOG_WARN("Exception while running");
  }
}

bool WebsocketClient::Stop() {
  if (!running_) {
    return false;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // cppcheck-suppress identicalConditionAfterEarlyExit
  if (!running_) {  // Double-check after acquiring lock
    return false;
  }
  SPDLOG_INFO("Marked client as stopped and disconnected");

  running_ = false;
  was_connected_ = false;

  boost::system::error_code ec;

  try {
    if (was_inited_) {
      watchdog_timer_.cancel();
    }
  } catch (const boost::system::system_error&) {
    SPDLOG_WARN("Cancellation timer error");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while stopping timer");
  }

  try {
    SPDLOG_INFO("Emit cancel signal");
    if (was_inited_) {
      cancel_signal_.emit(boost::asio::cancellation_type::all);
    }
  } catch (const std::exception&) {
    SPDLOG_DEBUG("Exception during cancellation");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during cancellation");
  }

  try {
    SPDLOG_INFO("Closing write_channel");
    if (was_inited_) {
      write_channel_.close();
    }
  } catch (const std::exception&) {
    SPDLOG_DEBUG("Exception closing write channel");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during closing write channel");
  }

  try {
    SPDLOG_INFO("Closing resolver");
    if (was_inited_) {
      resolver_.cancel();
    }
  } catch (const std::exception&) {
    SPDLOG_DEBUG("Exception cancelling resolver");
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during closing resolver");
  }

  // Close TCP connection
  try {
    if (was_inited_) {
      SPDLOG_INFO("Shutting down TCP socket...");
      auto& tcp = boost::beast::get_lowest_layer(ws_);
      if (tcp.socket().is_open()) {
        tcp.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != boost::asio::error::not_connected) {
          SPDLOG_WARN("TCP socket shutdown error: {}", ec.message());
        } else {
          SPDLOG_INFO("TCP socket shutdown successfully");
        }

        tcp.socket().close(ec);
        if (ec) {
          SPDLOG_WARN("TCP socket close error: {}", ec.message());
        } else {
          SPDLOG_INFO("TCP socket closed successfully");
        }
      }
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during TCP shutdown: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during TCP shutdown");
  }

  // Close SSL
  try {
    if (was_inited_) {
      SPDLOG_INFO("Shutting down SSL layer...");
      auto& ssl = ws_.next_layer();
      if (ssl.native_handle()) {
        // More robust SSL shutdown
        ::SSL_set_quiet_shutdown(ssl.native_handle(), 1);
        ::SSL_shutdown(ssl.native_handle());
      }
      ssl.shutdown(ec);
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during SSL shutdown: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Unexpected exception during SSL shutdown: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred during SSL shutdown");
  }

  if (auto* ssl = ws_.next_layer().native_handle()) {
    https::utils::AttachCertificateVerificationCallbackDelete(ssl);
  }
  was_stopped_ = true;
  SPDLOG_INFO("WebSocket client stopped successfully");
  return true;
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
      co_return false;
    }

    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(24));

    // Start timer
    StartWatchdog();

    // Start reader and sender
    was_inited_ = true;
    auto self = shared_from_this();
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunReader(); }, boost::asio::detached);
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunSender(); }, boost::asio::detached);
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunInternal exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while running");
  }
  co_return false;
}

boost::asio::awaitable<bool> WebsocketClient::Connect() {
  boost::system::error_code ec;
  try {
    // DNS resolution
    const std::string server_port_str =
        std::to_string(config_.common.server_port);
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
    auto results = co_await resolver_.async_resolve(
        config_.common.server_ip.ToString(), server_port_str,
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

    SPDLOG_INFO("Connected to {}:{}", config_.common.server_ip.ToString(),
        config_.common.server_port);

    // TCP options
    boost::beast::get_lowest_layer(ws_).socket().set_option(
        boost::asio::ip::tcp::no_delay(true));

    // Reality Mode: Enhanced stealth connection protocol
    // First, establishes a genuine TLS handshake as a decoy to bypass deep
    // packet inspection Then resets the connection state and activates
    // obfuscation for the real encrypted tunnel This dual-handshake approach
    // makes traffic analysis significantly more difficult
    if (config_.common.https_init_connection_strategy ==
        HttpsInitConnectionStrategy::kSniRealityMode) {
      const bool status = co_await PerformFakeHandshake();
      if (!status) {
        co_return false;
      }
      // For Reality Mode we use TLS obfuscator after fake handshake
      // This provides additional encryption layer for the real connection
      ws_.next_layer().next_layer().set_obfuscator(
          std::make_shared<protocol::https::obfuscator::TlsObfuscator>());
    } else if (obfuscator_ != nullptr) {  // Set obfuscator
      ws_.next_layer().next_layer().set_obfuscator(obfuscator_);
    }

    // SSL handshake
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(10));

    // timeout
    co_await boost::asio::steady_timer{
        co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(100)}
        .async_wait(boost::asio::use_awaitable);

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
    }
    ws_.next_layer().next_layer().set_obfuscator(nullptr);
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
          req.set("Authorization", "Bearer " + jwt_access_token_);
          req.set(
              "ClientIP", config_.common.tun_interface_address_ipv4.ToString());
          req.set("ClientIPv6",
              config_.common.tun_interface_address_ipv6.ToString());
          req.set("Client-Agent",
              fmt::format("FptnClient({}/{})", FPTN_USER_OS, FPTN_VERSION));
        }));
    co_await ws_.async_handshake(config_.common.server_ip.ToString(),
        kUrlWebSocket_,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("WebSocket handshake error: {}", ec.message());
      co_return false;
    }

    was_connected_ = true;
    SPDLOG_INFO("WebSocket connection established successfully");

    if (config_.common.on_connected_callback) {
      config_.common.on_connected_callback();
    }
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Connect exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception");
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
        if (running_ && packet && config_.common.recv_ip_packet_callback) {
          config_.common.recv_ip_packet_callback(std::move(packet));
        }
      }
      buffer.consume(buffer.size());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunReader exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("RunReader unknown exception");
  }
  was_connected_ = false;
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
  } catch (...) {
    SPDLOG_ERROR("RunSender unknown exception");
  }
  was_connected_ = false;
  co_return;
}

boost::asio::awaitable<bool> WebsocketClient::PerformFakeHandshake() {
  boost::system::error_code ec;
  try {
    SPDLOG_INFO(
        "Generating and sending fake TLS handshake to {}", config_.common.sni);
    const auto handshake_data =
        utils::GenerateDecoyTlsHandshake(config_.common.sni);
    if (handshake_data.empty()) {
      SPDLOG_WARN(
          "Failed to generate handshake data for SNI: {}", config_.common.sni);
      co_return false;
    }

    SPDLOG_INFO(
        "Sending {} bytes of handshake data over TCP", handshake_data.size());

    auto& tcp_layer = boost::beast::get_lowest_layer(ws_);
    auto& tcp_socket = tcp_layer.socket();

    const std::size_t bytes_sent = co_await boost::asio::async_write(tcp_socket,
        boost::asio::buffer(handshake_data),
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (ec) {
      SPDLOG_ERROR("Failed to send fake handshake: {}", ec.message());
      co_return false;
    }

    SPDLOG_INFO("Successfully sent {} bytes of handshake data", bytes_sent);

    do {
      std::array<std::uint8_t, 16384> buffer{};
      const std::size_t bytes_read = co_await tcp_socket.async_receive(
          boost::asio::buffer(buffer), boost::asio::use_awaitable);
      if (ec && ec != boost::asio::error::eof) {
        SPDLOG_WARN("Read during fake handshake failed: {}", ec.message());
      }
      if (bytes_read) {
        break;
      }
    } while (true);

    SPDLOG_INFO("Fake handshake completed successfully");
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("PerformFakeHandshake exception: {}", e.what());
  }
  co_return false;
}

void WebsocketClient::StartWatchdog() {
  if (!running_) {
    return;
  }

  constexpr std::chrono::milliseconds kTimeout(300);
  watchdog_timer_.expires_after(kTimeout);
  watchdog_timer_.async_wait([self = weak_from_this()](
                                 const boost::system::error_code& ec) {
    if (auto shared_self = self.lock()) {
      if (!ec && shared_self->running_) {
        // cppcheck-suppress knownConditionTrueFalse
        if (!shared_self->was_connected_.load() && shared_self->running_) {
          SPDLOG_INFO("Watchdog detected disconnected state, calling Stop()");
          shared_self->Stop();
        } else {
          shared_self->StartWatchdog();
        }
      }
    }
  });
}

}  // namespace fptn::protocol::https
