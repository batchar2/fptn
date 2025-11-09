/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"

#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/api_client/api_client.h"

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
      ws_(ssl_stream_type(
          obfuscator_socket_type(boost::asio::make_strand(ioc_), obfuscator_),
          ctx_)),
      strand_(boost::asio::make_strand(ioc_)),
      write_channel_(strand_, kMaxSizeOutQueue_),
      server_ip_(server_ip),
      server_port_str_(std::to_string(server_port)),
      tun_interface_address_ipv4_(tun_interface_address_ipv4),
      tun_interface_address_ipv6_(tun_interface_address_ipv6),
      new_ip_pkt_callback_(std::move(new_ip_pkt_callback)),
      sni_(std::move(sni)),
      access_token_(std::move(access_token)),
      expected_md5_fingerprint_(std::move(expected_md5_fingerprint)),
      on_connected_callback_(std::move(on_connected_callback)) {
  auto* ssl = ws_.next_layer().native_handle();
  fptn::protocol::https::utils::SetHandshakeSni(ssl, sni_);
  fptn::protocol::https::utils::SetHandshakeSessionID(ssl);

  fptn::protocol::https::utils::AttachCertificateVerificationCallback(
      ssl, [this](const std::string& md5_fingerprint) mutable {
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
    fptn::protocol::https::utils::AttachCertificateVerificationCallbackDelete(
        ssl);
  }
}

void WebsocketClient::Run() {
  if (running_.exchange(true)) {
    SPDLOG_WARN("WebsocketClient is already running");
    return;
  }

  SPDLOG_INFO("Connecting to {}:{}", server_ip_.toString(), server_port_str_);

  if (obfuscator_) {
    obfuscator_->Reset();
  }

  // Запускаем внутреннюю корутину
  boost::asio::co_spawn(
      ioc_,
      [self = shared_from_this()]() -> boost::asio::awaitable<void> {
        return self->RunInternal();
      },
      boost::asio::detached);
  ioc_.run();
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

  boost::system::error_code ec;

  // Close WebSocket
  try {
    if (ws_.is_open()) {
      boost::beast::get_lowest_layer(ws_).expires_never();
      ws_.close(boost::beast::websocket::close_code::normal, ec);
      if (ec) {
        SPDLOG_WARN("WebSocket close error: {}", ec.message());
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during WebSocket close: {}", e.what());
  }

  // Close SSL
  try {
    auto& ssl = ws_.next_layer();
    if (ssl.native_handle()) {
      ::SSL_set_quiet_shutdown(ssl.native_handle(), 1);
      // ::SSL_shutdown(ssl.native_handle());
    }
    ssl.shutdown(ec);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during SSL shutdown: {}", e.what());
  }

  // Close TCP
  try {
    auto& tcp = boost::beast::get_lowest_layer(ws_);
    tcp.close();
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during TCP shutdown: {}", e.what());
  }

  // Stop IO context
  try {
    ioc_.stop();
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception while stopping IO context: {}", e.what());
  }

  SPDLOG_INFO("WebsocketClient stopped successfully");
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

bool WebsocketClient::IsStarted() const {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return running_ && was_connected_;
}

boost::asio::awaitable<void> WebsocketClient::RunInternal() {
  try {
    bool connected = co_await Connect();
    if (!connected) {
      running_ = false;
      co_return;
    }

    // reset obfuscator after connect
    ws_.next_layer().next_layer().set_obfuscator(nullptr);

    // Start reader and sender
    auto self = shared_from_this();
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunReader(); }, boost::asio::detached);
    boost::asio::co_spawn(
        strand_, [self]() { return self->RunSender(); }, boost::asio::detached);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunInternal exception: {}", e.what());
    running_ = false;
  }
}

boost::asio::awaitable<bool> WebsocketClient::Connect() {
  boost::system::error_code ec;

  try {
    // DNS resolution
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
    auto results = co_await resolver_.async_resolve(server_ip_.toString(),
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

    SPDLOG_INFO("Connected to {}:{}", server_ip_.toString(), server_port_str_);

    // TCP options
    boost::beast::get_lowest_layer(ws_).socket().set_option(
        boost::asio::ip::tcp::no_delay(true));

    // SSL handshake
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(10));
    co_await ws_.next_layer().async_handshake(
        boost::asio::ssl::stream_base::client,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("SSL handshake error: {}", ec.message());
      co_return false;
    }

    SPDLOG_INFO("SSL handshake completed");

    // WebSocket handshake
    ws_.set_option(boost::beast::websocket::stream_base::decorator(
        [this](boost::beast::websocket::request_type& req) {
          const auto headers = fptn::protocol::https::RealBrowserHeaders(sni_);
          for (const auto& [key, value] : headers) {
            req.set(key, value);
          }
          req.set("Authorization", "Bearer " + access_token_);
          req.set("ClientIP", tun_interface_address_ipv4_.toString());
          req.set("ClientIPv6", tun_interface_address_ipv6_.toString());
          req.set("Client-Agent", "FptnClient/1.0");
        }));

    co_await ws_.async_handshake(server_ip_.toString(), kUrlWebSocket_,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec) {
      SPDLOG_ERROR("WebSocket handshake error: {}", ec.message());
      co_return false;
    }

    // WebSocket options
    boost::beast::websocket::stream_base::timeout timeout_option;
    timeout_option.handshake_timeout = std::chrono::seconds(10);
    timeout_option.idle_timeout = std::chrono::seconds(30);
    timeout_option.keep_alive_pings = true;
    ws_.set_option(timeout_option);

    boost::beast::get_lowest_layer(ws_).expires_never();

    was_connected_ = true;
    SPDLOG_INFO("WebSocket connection established successfully");

    if (on_connected_callback_) {
      on_connected_callback_();
    }
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Connect exception: {}", e.what());
    co_return false;
  }
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
