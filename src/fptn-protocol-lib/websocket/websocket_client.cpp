/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/websocket/websocket_client.h"

#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/https_client.h"
#include "fptn-protocol-lib/protobuf/protocol.h"
#include "fptn-protocol-lib/tls/tls.h"

using fptn::protocol::websocket::WebsocketClient;

WebsocketClient::WebsocketClient(pcpp::IPv4Address server_ip,
    int server_port,
    pcpp::IPv4Address tun_interface_address_ipv4,
    pcpp::IPv6Address tun_interface_address_ipv6,
    NewIPPacketCallback new_ip_pkt_callback,
    std::string sni,
    std::string access_token,
    std::string expected_md5_fingerprint,
    OnConnectedCallback on_connected_callback)
    : ctx_(fptn::protocol::tls::CreateNewSslCtx()),
      resolver_(boost::asio::make_strand(ioc_)),
      ws_(boost::asio::make_strand(ioc_), ctx_),
      strand_(ioc_.get_executor()),
      running_(false),
      server_ip_(std::move(server_ip)),
      server_port_str_(std::to_string(server_port)),
      tun_interface_address_ipv4_(std::move(tun_interface_address_ipv4)),
      tun_interface_address_ipv6_(std::move(tun_interface_address_ipv6)),
      new_ip_pkt_callback_(std::move(new_ip_pkt_callback)),
      sni_(std::move(sni)),
      access_token_(std::move(access_token)),
      expected_md5_fingerprint_(std::move(expected_md5_fingerprint)),
      on_connected_callback_(std::move(on_connected_callback)) {
  fptn::protocol::tls::SetHandshakeSni(ws_.next_layer().native_handle(), sni_);
  fptn::protocol::tls::SetHandshakeSessionID(ws_.next_layer().native_handle());

  // Validate the server certificate
  ssl_ = ws_.next_layer().native_handle();
  fptn::protocol::tls::AttachCertificateVerificationCallback(
      ssl_, [this](const std::string& md5_fingerprint) {
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
}

WebsocketClient::~WebsocketClient() {
  if (ssl_) {
    fptn::protocol::tls::AttachCertificateVerificationCallbackDelete(ssl_);
    ssl_ = nullptr;
  }
}

void WebsocketClient::Run() {
  try {
    SPDLOG_INFO("Connection: {}:{}", server_ip_.toString(), server_port_str_);

    auto self = shared_from_this();
    resolver_.async_resolve(server_ip_.toString(), server_port_str_,
        [self](boost::beast::error_code ec,
            boost::asio::ip::tcp::resolver::results_type results) mutable {
          if (ec) {
            SPDLOG_ERROR("Resolve error: {}", ec.message());
          } else {
            self->onResolve(ec, std::move(results));
          }
        });
    ioc_.run();
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Error run ws_: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Undefined ws error");
  }
}

bool WebsocketClient::Stop() {
  if (!running_) {
    return false;
  }

  std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // cppcheck-suppress identicalConditionAfterEarlyExit
  if (!running_) {  // Double-check after acquiring lock
    return false;
  }

  running_ = false;
  boost::system::error_code ec;

  // Close WebSocket by triggering a timeout
  try {
    boost::beast::get_lowest_layer(ws_).expires_after(
        std::chrono::microseconds(1));
    SPDLOG_DEBUG("WebSocket expiration timer set to 1 microsecond");
  } catch (const std::exception& err) {
    SPDLOG_ERROR("Failed to set WebSocket expiration timer: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown error while setting WebSocket expiration timer");
  }

  // Close websocket
  try {
    if (ws_.is_open()) {
      ws_.close(boost::beast::websocket::close_code::normal, ec);
      if (ec) {
        SPDLOG_WARN("WebSocket close returned error: {}", ec.message());
      } else {
        SPDLOG_INFO("WebSocket closed successfully");
      }
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during WebSocket close (boost::system_error): {}",
        err.what());
  } catch (const std::exception& err) {
    SPDLOG_ERROR("Exception during WebSocket close: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred during WebSocket close");
  }

  // Close SSL
  try {
    auto& ssl = ws_.next_layer();
    if (ssl.native_handle()) {
      // More robust SSL shutdown
      ::SSL_set_quiet_shutdown(ssl.native_handle(), 1);
      ::SSL_shutdown(ssl.native_handle());
    }
    ssl.shutdown(ec);
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during SSL shutdown: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Unexpected exception during SSL shutdown: {}", e.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred during SSL shutdown");
  }

  // Close TCP connection
  try {
    auto& tcp = ws_.next_layer().next_layer();
    tcp.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec) {
      SPDLOG_WARN("TCP socket shutdown error: {}", ec.message());
    } else {
      SPDLOG_DEBUG("TCP socket shutdown successfully");
    }
    tcp.socket().close(ec);
    if (ec) {
      SPDLOG_WARN("TCP socket close error: {}", ec.message());
    } else {
      SPDLOG_DEBUG("TCP socket closed successfully");
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during TCP shutdown: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during TCP shutdown");
  }

  // Stop io_context
  try {
    ioc_.stop();
    SPDLOG_DEBUG("io_context stopped");
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception while stopping io_context: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while stopping io_context");
  }
  return true;
}

void WebsocketClient::onResolve(boost::beast::error_code ec,
    // NOLINTNEXTLINE(performance-unnecessary-value-param)
    boost::asio::ip::tcp::resolver::results_type results) {
  if (ec) {
    return Fail(ec, "resolve");
  }
  // Set a timeout on the operation
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
  // Make the connection on the IP address we get from a lookup
  boost::beast::get_lowest_layer(ws_).async_connect(
      results, boost::beast::bind_front_handler(
                   &WebsocketClient::onConnect, shared_from_this()));
}

void WebsocketClient::onConnect(boost::beast::error_code ec,
    // NOLINTNEXTLINE(performance-unnecessary-value-param)
    boost::asio::ip::tcp::resolver::results_type::endpoint_type) {
  if (ec) {
    return Fail(ec, "connect");
  }

  try {
    // Set a timeout on the operation
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

    ws_.text(false);
    ws_.binary(true);                  // Only binary
    ws_.auto_fragment(true);           // FIXME NEED CHECK
    ws_.read_message_max(128 * 1024);  // MaxSize (128 KB)
    ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
        boost::beast::role_type::client));
    boost::beast::get_lowest_layer(ws_).socket().set_option(
        boost::asio::ip::tcp::no_delay(true));  // turn off the Nagle algorithm.

    ws_.next_layer().async_handshake(boost::asio::ssl::stream_base::client,
        boost::beast::bind_front_handler(
            &WebsocketClient::onSslHandshake, shared_from_this()));
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("onConnect error: {}", err.what());
    Stop();
  }
}

void WebsocketClient::onSslHandshake(boost::beast::error_code ec) {
  if (ec) {
    return Fail(ec, "onSslHandshake");
  }
  // Turn off the timeout on the tcp_stream, because
  // the websocket stream has its own timeout system.
  boost::beast::get_lowest_layer(ws_).expires_never();

  // Set suggested timeout settings for the websocket
  ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
      boost::beast::role_type::client));

  // Set https headers
  auto self = shared_from_this();
  ws_.set_option(boost::beast::websocket::stream_base::decorator(
      [self](boost::beast::websocket::request_type& req) mutable {
        // set browser headers
        using fptn::protocol::https::HttpsClient;
        const auto headers =
            fptn::protocol::https::RealBrowserHeaders(self->sni_);
        for (const auto& [key, value] : headers) {
          req.set(key, value);
        }
        // set custom headers
        req.set("Authorization", "Bearer " + self->access_token_);
        req.set("ClientIP", self->tun_interface_address_ipv4_.toString());
        req.set("ClientIPv6", self->tun_interface_address_ipv6_.toString());
        req.set("Client-Agent",
            fmt::format("FptnClient({}/{})", FPTN_USER_OS, FPTN_VERSION));
      }));

  // Perform the websocket handshake
  ws_.async_handshake(server_ip_.toString(), kUrlWebSocket_,
      boost::beast::bind_front_handler(
          &WebsocketClient::onHandshake, shared_from_this()));
}

void WebsocketClient::onHandshake(boost::beast::error_code ec) {
  if (ec) {
    return Fail(ec, "onHandshake");
  }
  running_ = true;
  SPDLOG_INFO("WebSocket connection started successfully");

  // set timeout
  // NOLINTNEXTLINE(modernize-use-designated-initializers)
  ws_.set_option(boost::beast::websocket::stream_base::timeout{
      std::chrono::seconds(10),  // handshake_timeout
      std::chrono::seconds(5),   // idle_timeout
      true                       // keep_alive_pings
  });

  if (nullptr != on_connected_callback_) {
    on_connected_callback_();
  }
  DoRead();
}

void WebsocketClient::onRead(
    boost::beast::error_code ec, std::size_t transferred) {
  if (ec) {
    return Fail(ec, "read");
  }
  if (running_) {
    // FIXME REDUNDANT COPY
    const auto data = boost::beast::buffers_to_string(buffer_.data());
    std::string raw = fptn::protocol::protobuf::GetProtoPayload(data);
    auto packet = fptn::common::network::IPPacket::Parse(std::move(raw));
    if (packet) {
      new_ip_pkt_callback_(std::move(packet));
    }
    buffer_.consume(transferred);
    DoRead();
  }
}

void WebsocketClient::Fail(boost::beast::error_code ec, char const* what) {
  if (running_) {
    SPDLOG_ERROR("Fail {}: {}", what, ec.what());
  }
  Stop();
}

void WebsocketClient::DoRead() {
  if (running_) {
    ws_.async_read(buffer_, boost::beast::bind_front_handler(
                                &WebsocketClient::onRead, shared_from_this()));
  }
}

bool WebsocketClient::Send(fptn::common::network::IPPacketPtr packet) {
  if (out_queue_.size() < out_queue_max_size_ && running_) {
    boost::asio::post(strand_,
        [self = shared_from_this(), msg = std::move(packet)]() mutable {
          const std::unique_lock<std::mutex> lock(self->mutex_);  // mutex

          const bool was_empty = self->out_queue_.empty();
          self->out_queue_.push(std::move(msg));
          if (was_empty) {
            self->DoWrite();
          }
        });
    return true;
  }
  return false;
}

void WebsocketClient::DoWrite() {
  try {
    if (!out_queue_.empty() && running_) {
      // PACK DATA
      fptn::common::network::IPPacketPtr packet = std::move(out_queue_.front());
      const std::string msg =
          fptn::protocol::protobuf::CreateProtoPayload(std::move(packet));
      const boost::asio::const_buffer buffer(msg.data(), msg.size());

      ws_.async_write(
          buffer, boost::beast::bind_front_handler(
                      &WebsocketClient::onWrite, shared_from_this()));
    }
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("doWrite system_error: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("doWrite error: {}", e.what());
  }
}

void WebsocketClient::onWrite(boost::beast::error_code ec, std::size_t) {
  if (ec) {
    return Fail(ec, "onWrite");
  }

  if (running_) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    out_queue_.pop();  // remove written item
    if (!out_queue_.empty() && running_) {
      DoWrite();  // send next message
    }
  }
}

bool WebsocketClient::IsStarted() { return running_; }
