/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

#include <https/utils/change_cipher_spec.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <camouflage/tls/builder.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/network/utils.h"  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/api_client/api_client.h"
#include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"

namespace fptn::protocol::https {

WebsocketClient::WebsocketClient(fptn::common::network::IPv4Address server_ip,
    int server_port,
    fptn::common::network::IPv4Address tun_interface_address_ipv4,
    fptn::common::network::IPv6Address tun_interface_address_ipv6,
    NewIPPacketCallback new_ip_pkt_callback,
    std::string sni,
    std::string access_token,
    std::string expected_md5_fingerprint,
    CensorshipStrategy censorship_strategy,
    OnConnectedCallback on_connected_callback,
    int thread_number)
    : ioc_(thread_number),
      ctx_(https::utils::CreateNewSslCtx()),
      resolver_(boost::asio::make_strand(ioc_)),
      censorship_strategy_(censorship_strategy),
      ws_(ssl_stream_type(
          obfuscator_socket_type(boost::asio::make_strand(ioc_), nullptr),
          ctx_)),
      strand_(boost::asio::make_strand(ioc_)),
      watchdog_timer_(strand_),
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

  // Set SSL buffer sizes
  SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);

  if (censorship_strategy_ == CensorshipStrategy::kSni) {
    obfuscator_ = nullptr;
  }
  if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
    obfuscator_ =
        std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator>();
    ws_.next_layer().next_layer().set_obfuscator(obfuscator_);
  }

  if (censorship_strategy_ == CensorshipStrategy::kSniRealityMode) {
    obfuscator_ = nullptr;
  }

  https::utils::AttachCertificateVerificationCallback(
      ssl, [this](const std::string& md5_fingerprint) mutable {
        if (expected_md5_fingerprint_.empty()) {
          return true;
        }
        if (md5_fingerprint == expected_md5_fingerprint_) {
          return true;
        }
        SPDLOG_ERROR("Certificate MD5 mismatch. Expected: {}, got: {}.",
            expected_md5_fingerprint_, md5_fingerprint);
        return false;
      });

  ws_.text(false);
  ws_.binary(true);
  ws_.auto_fragment(true);
  ws_.read_message_max(256 * 1024);
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

  SPDLOG_INFO("Connecting to {}:{}", server_ip_.ToString(), server_port_str_);

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
    ioc_.restart();
    while (running_) {
      ioc_.run_one();
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

  new_ip_pkt_callback_ = nullptr;
  on_connected_callback_ = nullptr;

  boost::system::error_code ec;

  try {
    watchdog_timer_.cancel();
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

      boost::asio::socket_base::linger linger(true, 0);
      tcp.socket().set_option(linger);

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

    // Optimize socket buffer sizes
    try {
      boost::beast::get_lowest_layer(ws_).socket().set_option(
          boost::asio::socket_base::receive_buffer_size(1 * 1024 * 1024));
      boost::beast::get_lowest_layer(ws_).socket().set_option(
          boost::asio::socket_base::send_buffer_size(1 * 1024 * 1024));
    } catch (const boost::system::system_error& e) {
      SPDLOG_WARN("Failed to set socket options: {}", e.what());
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
  try {
    boost::system::error_code ec;

    // DNS resolution
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
    const auto results = co_await resolver_.async_resolve(server_ip_.ToString(),
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

    auto& socket = boost::beast::get_lowest_layer(ws_).socket();
    if (!socket.is_open()) {
      SPDLOG_ERROR("Socket not open after connect");
      co_return false;
    }

    const auto remote_ep = socket.remote_endpoint(ec);
    if (ec) {
      SPDLOG_ERROR("Socket reported connected but remote_endpoint() failed: {}",
          ec.message());
      co_return false;
    }

    SPDLOG_INFO("Successfully connected to {}:{}",
        remote_ep.address().to_string(), remote_ep.port());

    // TCP options
    socket.set_option(boost::asio::ip::tcp::no_delay(true));
    socket.set_option(boost::asio::socket_base::reuse_address(true));

    // Optimize socket buffers
    try {
      constexpr int kBufferSize = 4 * 1024 * 1024;
      socket.set_option(
          boost::asio::socket_base::receive_buffer_size(kBufferSize));
      socket.set_option(
          boost::asio::socket_base::send_buffer_size(kBufferSize));
    } catch (...) {
      SPDLOG_WARN("Failed to set socket buffer sizes in Connect()");
    }

    // Reality Mode: Enhanced stealth connection protocol
    // First, establishes a genuine TLS handshake as a decoy to bypass deep
    // packet inspection Then resets the connection state and activates
    // obfuscation for the real encrypted tunnel This dual-handshake approach
    // makes traffic analysis significantly more difficult
    if (IsRealityModeWithFakeHandshake(censorship_strategy_)) {
      const bool status = co_await PerformFakeHandshake2();
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
        std::chrono::milliseconds(10)}
        .async_wait(boost::asio::use_awaitable);

    co_await ws_.next_layer().async_handshake(
        boost::asio::ssl::stream_base::client,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (ec) {
      SPDLOG_ERROR("SSL handshake error: {}", ec.message());
      co_return false;
    }

    // CLEAN WEBSOCKET
    common::network::CleanSocket(socket);
    common::network::CleanSsl(ws_.next_layer().native_handle());

    // Reset obfuscator after TLS-handshake
    ws_.next_layer().next_layer().set_obfuscator(nullptr);

    // timeout
    co_await boost::asio::steady_timer{
        co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(100)}
        .async_wait(boost::asio::use_awaitable);

    SPDLOG_INFO("SSL handshake completed");

    // WebSocket connection options
    try {
      boost::beast::websocket::stream_base::timeout timeout_option;
      timeout_option.handshake_timeout = std::chrono::seconds(10);
      timeout_option.idle_timeout = std::chrono::seconds(10);
      timeout_option.keep_alive_pings = true;
      ws_.set_option(timeout_option);
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Failed to set timeout: {}", e.what());
    }
    // WebSocket handshake
    ws_.set_option(boost::beast::websocket::stream_base::decorator(
        [this](boost::beast::websocket::request_type& req) {
          req.set("Authorization", "Bearer " + access_token_);
          req.set("ClientIP", tun_interface_address_ipv4_.ToString());
          req.set("ClientIPv6", tun_interface_address_ipv6_.ToString());
          req.set("Client-Agent",
              fmt::format("FptnClient({}/{})", FPTN_USER_OS, FPTN_VERSION));
        }));
    // Websocket handshake
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

    // WebSocket options
    try {
      boost::beast::websocket::stream_base::timeout timeout_option;
      timeout_option.handshake_timeout = std::chrono::seconds(10);
      timeout_option.idle_timeout = std::chrono::seconds(4);
      timeout_option.keep_alive_pings = true;
      ws_.set_option(timeout_option);
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Failed to set timeout: {}", e.what());
    }

    // timeout
    co_await boost::asio::steady_timer{
        co_await boost::asio::this_coro::executor,
        std::chrono::milliseconds(10)}
        .async_wait(boost::asio::use_awaitable);

    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Connect exception: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception");
  }
  co_return false;
}

boost::asio::awaitable<void> WebsocketClient::RunReader() {
  boost::beast::flat_buffer buffer;
  buffer.reserve(4 * 1024 * 1024);
  try {
    boost::system::error_code ec;
    while (running_ && was_connected_ && ws_.is_open()) {
      co_await ws_.async_read(
          buffer, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

      if (ec) {
        if (ec != boost::beast::websocket::error::closed) {
          SPDLOG_DEBUG("WebSocket read error: {}", ec.message());
        }
        break;
      }
      if (!buffer.size()) {
        continue;
      }
      try {
        auto raw_ip = protobuf::GetProtoPayload(buffer);
        if (raw_ip.has_value()) {
          auto packet =
              fptn::common::network::IPPacket::Parse(std::move(raw_ip.value()));
          if (running_ && packet && new_ip_pkt_callback_) {
            new_ip_pkt_callback_(std::move(packet));
          }
        }
      } catch (const std::exception& e) {
        SPDLOG_WARN("IP packet error: {}", e.what());
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
        auto msg =
            fptn::protocol::protobuf::CreateProtoPayload(std::move(packet));
        if (msg.has_value()) {
          co_await ws_.async_write(boost::asio::buffer(std::move(msg.value())),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        }
      }

      if (ec) {
        SPDLOG_ERROR("WebSocket error: {}", ec.message());
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

boost::asio::awaitable<bool> WebsocketClient::PerformFakeHandshake2() {
  try {
    boost::system::error_code ec;
    auto& tcp_layer = boost::beast::get_lowest_layer(ws_);
    auto& tcp_socket = tcp_layer.socket();

    SPDLOG_INFO("Fake TLS handshake started for SNI: {}", sni_);

    /* Send client hello */
    const auto client_hello = GenerateHandshakePacket();
    if (client_hello.empty()) {
      SPDLOG_WARN("Failed to generate ClientHello for SNI: {}", sni_);
      co_return false;
    }
    const std::size_t client_hello_bytes_size =
        co_await boost::asio::async_write(tcp_socket,
            boost::asio::buffer(client_hello),
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Failed to send ClientHello to {}: {}", sni_, ec.message());
      co_return false;
    }
    if (client_hello_bytes_size != client_hello.size()) {
      SPDLOG_ERROR("Error ClientHello sent: {} of {} bytes",
          client_hello_bytes_size, client_hello.size());
      co_return false;
    }

    /* Wait for server answer */
    const auto server_hello =
        co_await common::network::WaitForServerTlsHelloAsync(tcp_socket);
    if (!server_hello.has_value()) {
      SPDLOG_ERROR("Failed to receive ServerHello from {}", sni_);
      co_return false;
    }

    /* Send change cipher spec */
    const auto change_cipher_spec =
        fptn::protocol::https::utils::MakeClientChangeCipherSpec();
    const std::size_t change_cipher_spec_size =
        co_await boost::asio::async_write(tcp_socket,
            boost::asio::buffer(change_cipher_spec),
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("Failed to send ClientHello to {}: {}", sni_, ec.message());
      co_return false;
    }
    if (change_cipher_spec_size != change_cipher_spec.size()) {
      SPDLOG_ERROR("Failed to send ClientHello to {}: {}",
          change_cipher_spec_size, change_cipher_spec.size());
      co_return false;
    }

    // timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    SPDLOG_INFO(
        "Fake TLS handshake completed for {}, received {} bytes from server",
        sni_, server_hello.value().size());
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Fake TLS handshake exception for {}: {}", sni_, e.what());
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

std::vector<std::uint8_t> WebsocketClient::GenerateHandshakePacket() const {
  auto builder = camouflage::tls::Builder::Create();
  switch (censorship_strategy_) {
    /* Chrome */
    case CensorshipStrategy::kSniRealityModeChrome147:
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_147_0_7727_56);
      break;
    case CensorshipStrategy::kSniRealityModeChrome146:
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_146_0_7680_178);
      break;
    case CensorshipStrategy::kSniRealityModeChrome145:
      builder.GoogleChrome(
          camouflage::tls::google_chrome::Version::kV_145_0_7632_46);
      break;
    /* Firefox */
    case CensorshipStrategy::kSniRealityModeFirefox149:
      builder.Firefox(camouflage::tls::firefox::Version::kV_149_0);
      break;
    /* Yandex */
    case CensorshipStrategy::kSniRealityModeYandex26:
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_26_3_3_881);
      break;
    case CensorshipStrategy::kSniRealityModeYandex25:
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_25_8_3_828);
      break;
    case CensorshipStrategy::kSniRealityModeYandex24:
      builder.YandexBrowser(
          camouflage::tls::yandex_browser::Version::kV_24_12_0_1772);
      break;
    /* Safari */
    case CensorshipStrategy::kSniRealityModeSafari26:
      builder.Safari(camouflage::tls::safari::Version::kV_26_4);
      break;
    /* Default */
    default:
      SPDLOG_DEBUG("Using fallback handshake generator for SNI: {}", sni_);
      return utils::GenerateDecoyTlsHandshake(sni_);
  }

  const auto session_id = utils::GenerateDecoyTlsSessionId2();
  if (!session_id.has_value()) {
    SPDLOG_WARN("Session ID generation failed");
    return utils::GenerateDecoyTlsHandshake(sni_);
  }

  const auto handshake =
      builder.SetSNI(sni_).SetSessionId(session_id.value()).Generate();
  if (!handshake.has_value()) {
    SPDLOG_WARN(
        "Handshake generation failed for SNI: {}, using fallback", sni_);
    return utils::GenerateDecoyTlsHandshake(sni_);
  }

  SPDLOG_INFO("Handshake generated: SNI={}, size={} bytes", sni_,
      handshake->handshake_packet_size);

  return std::vector<std::uint8_t>(handshake->handshake_packet,
      handshake->handshake_packet + handshake->handshake_packet_size);
}

}  // namespace fptn::protocol::https
