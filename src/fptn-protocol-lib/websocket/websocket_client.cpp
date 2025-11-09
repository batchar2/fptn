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

WebsocketClient::WebsocketClient(fptn::common::network::IPv4Address server_ip,
    int server_port,
    fptn::common::network::IPv4Address tun_interface_address_ipv4,
    fptn::common::network::IPv6Address tun_interface_address_ipv6,
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
      was_connected_(false),
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
  fptn::protocol::tls::SetHandshakeSni(ssl, sni_);
  fptn::protocol::tls::SetHandshakeSessionID(ssl);
  // Validate the server certificate
  ssl_ = ws_.next_layer().native_handle();
  fptn::protocol::tls::AttachCertificateVerificationCallback(
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
}

WebsocketClient::~WebsocketClient() {
  Stop();
  if (ssl_) {
    fptn::protocol::tls::AttachCertificateVerificationCallbackDelete(ssl_);
    ssl_ = nullptr;
  }
}

void WebsocketClient::Run() {
  try {
    running_ = true;
    SPDLOG_INFO("Connection: {}:{}", server_ip_.ToString(), server_port_str_);

    auto self = shared_from_this();

    const auto timeout = std::chrono::seconds(2);
    auto resolve_timeout = std::make_shared<boost::asio::steady_timer>(ioc_);
    resolve_timeout->expires_after(timeout);

    resolve_timeout->async_wait(
        [self, timeout](const boost::system::error_code& ec) mutable {
          if (ec) {
            // Timer was cancelled - this is normal operation when resolve
            // completes
            if (ec != boost::asio::error::operation_aborted) {
              SPDLOG_WARN("Unexpected timer error: {}", ec.message());
            } else {
              SPDLOG_INFO("Resolution timer cancelled (normal operation)");
            }
          } else {
            // Timeout triggered - resolution took too long
            SPDLOG_ERROR("DNS resolution failed to complete within {} seconds",
                timeout.count());
            try {
              self->resolver_.cancel();
              SPDLOG_DEBUG("DNS resolution cancelled due to timeout");
            } catch (const std::exception& e) {
              SPDLOG_ERROR("Failed to cancel resolver: {}", e.what());
            }
            self->Stop();
          }
        });

    // Resolve operations
    resolver_.async_resolve(server_ip_.ToString(), server_port_str_,
        [self, resolve_timeout](boost::beast::error_code ec,
            boost::asio::ip::tcp::resolver::results_type results) mutable {
          try {
            resolve_timeout->cancel();
          } catch (const std::exception& e) {
            SPDLOG_WARN("Failed to cancel resolver timer: {}", e.what());
          } catch (...) {
            SPDLOG_WARN("Unknown exception while cancelling resolve timer");
          }

          if (ec) {
            SPDLOG_ERROR("Resolve error: {}", ec.message());
            self->Stop();
            return;
          }

          try {
            SPDLOG_DEBUG("DNS resolution successful, proceeding to connection");
            self->onResolve(ec, std::move(results));
          } catch (const std::exception& e) {
            SPDLOG_ERROR("Exception in onResolve: {}", e.what());
            self->Stop();
          } catch (...) {
            SPDLOG_ERROR("Unknown critical error in onResolve");
            self->Stop();
          }
        });
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

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // cppcheck-suppress identicalConditionAfterEarlyExit
  if (!running_) {  // Double-check after acquiring lock
    return false;
  }
  SPDLOG_INFO("Marked client as stopped and disconnected");

  running_ = false;
  was_connected_ = false;

  boost::system::error_code ec;

  // Close WebSocket by triggering a timeout
  try {
    boost::beast::get_lowest_layer(ws_).expires_after(
        std::chrono::microseconds(1));
  } catch (const std::exception& err) {
    SPDLOG_ERROR("Failed to set WebSocket expiration timer: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown error while setting WebSocket expiration timer");
  }

  // Close SSL
  try {
    SPDLOG_DEBUG("Shutting down SSL layer...");
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
    SPDLOG_DEBUG("Shutting down TCP socket...");
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
    SPDLOG_DEBUG("Stopping io_context...");
    ioc_.stop();
    SPDLOG_DEBUG("io_context stopped");
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception while stopping io_context: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Unknown exception while stopping io_context");
  }

  SPDLOG_INFO("WebSocket client stopped successfully");
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
    SPDLOG_ERROR("Exception during onConnect: {}", err.what());
    Stop();
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Unexpected exception during onConnect: {}", e.what());
    Stop();
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred during onConnect");
    Stop();
  }
}

void WebsocketClient::onSslHandshake(boost::beast::error_code ec) {
  if (ec) {
    return Fail(ec, "onSslHandshake");
  }
  try {
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
          try {
            using fptn::protocol::https::HttpsClient;
            if (self->running_) {
              // set browser headers
              const auto headers =
                  fptn::protocol::https::RealBrowserHeaders(self->sni_);
              for (const auto& [key, value] : headers) {
                req.set(key, value);
              }
              // set custom headers
              req.set("Authorization", "Bearer " + self->access_token_);
              req.set("ClientIP", self->tun_interface_address_ipv4_.ToString());
              req.set(
                  "ClientIPv6", self->tun_interface_address_ipv6_.ToString());
              req.set("Client-Agent",
                  fmt::format("FptnClient({}/{})", FPTN_USER_OS, FPTN_VERSION));
            }
          } catch (const boost::system::system_error& err) {
            SPDLOG_ERROR("Exception during decorator: {}", err.what());
          } catch (const std::exception& e) {
            SPDLOG_ERROR("Unexpected exception during decorator: {}", e.what());
          } catch (...) {
            SPDLOG_ERROR("Unknown exception occurred during decorator");
          }
        }));

    // Perform the websocket handshake
    ws_.async_handshake(server_ip_.ToString(), kUrlWebSocket_,
        boost::beast::bind_front_handler(
            &WebsocketClient::onHandshake, shared_from_this()));
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during onSslHandshake: {}", err.what());
    Stop();
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Unexpected exception during onSslHandshake: {}", e.what());
    Stop();
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred during onSslHandshake");
    Stop();
  }
}

void WebsocketClient::onHandshake(boost::beast::error_code ec) {
  if (ec) {
    return Fail(ec, "onHandshake");
  }
  was_connected_ = true;
  SPDLOG_INFO("WebSocket connection started successfully");

  try {
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
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Exception during onHandshake: {}", err.what());
    Stop();
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Unexpected exception during onHandshake: {}", e.what());
    Stop();
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred during onHandshake");
    Stop();
  }
}

void WebsocketClient::onRead(
    boost::beast::error_code ec, std::size_t transferred) {
  if (ec) {
    return Fail(ec, "read");
  }

  if (running_) {
    try {
      // FIXME REDUNDANT COPY
      const auto data = boost::beast::buffers_to_string(buffer_.data());
      std::string raw = fptn::protocol::protobuf::GetProtoPayload(data);
      auto packet = fptn::common::network::IPPacket::Parse(std::move(raw));
      if (running_ && packet) {
        new_ip_pkt_callback_(std::move(packet));
      }
      buffer_.consume(transferred);
      DoRead();
    } catch (const boost::system::system_error& err) {
      SPDLOG_ERROR("Exception during onRead: {}", err.what());
      Stop();
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Unexpected exception during onRead: {}", e.what());
      Stop();
    } catch (...) {
      SPDLOG_ERROR("Unknown exception occurred during onRead");
      Stop();
    }
  }
}

void WebsocketClient::Fail(boost::beast::error_code ec, char const* what) {
  if (running_) {
    SPDLOG_ERROR("Fail {}: {}", what, ec.what());
  }
  Stop();
}

void WebsocketClient::DoRead() {
  if (running_ && was_connected_) {
    try {
      ws_.async_read(
          buffer_, boost::beast::bind_front_handler(
                       &WebsocketClient::onRead, shared_from_this()));
    } catch (const boost::system::system_error& err) {
      SPDLOG_ERROR("Exception during DoRead: {}", err.what());
      Stop();
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Unexpected exception during DoRead: {}", e.what());
      Stop();
    } catch (...) {
      SPDLOG_ERROR("Unknown exception occurred during DoRead");
      Stop();
    }
  }
}

bool WebsocketClient::Send(fptn::common::network::IPPacketPtr packet) {
  if (out_queue_.size() < kMaxSizeOutQueue_ && running_) {
    boost::asio::post(strand_,
        [self = shared_from_this(), msg = std::move(packet)]() mutable {
          if (!self->running_ || !self->was_connected_) {
            return;
          }

          const std::unique_lock<std::mutex> lock(self->mutex_);  // mutex

          if (!self->running_ || !self->was_connected_) {
            // Double-check after acquiring lock
            return;
          }

          const bool was_empty = self->out_queue_.empty();
          self->out_queue_.push(std::move(msg));
          if (was_empty && self->running_ && self->was_connected_) {
            self->DoWrite();
          }
        });
    return true;
  }
  return false;
}

void WebsocketClient::DoWrite() {
  try {
    if (!out_queue_.empty() && running_ && was_connected_) {
      // PACK DATA
      fptn::common::network::IPPacketPtr packet = std::move(out_queue_.front());
      const std::string msg =
          fptn::protocol::protobuf::CreateProtoPayload(std::move(packet));
      const boost::asio::const_buffer buffer(msg.data(), msg.size());

      if (running_ && was_connected_) {
        ws_.async_write(
            buffer, boost::beast::bind_front_handler(
                        &WebsocketClient::onWrite, shared_from_this()));
      }
    }
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("doWrite system_error: {}", err.what());
    Stop();
  } catch (const std::exception& e) {
    SPDLOG_ERROR("doWrite error: {}", e.what());
    Stop();
  } catch (...) {
    SPDLOG_ERROR("Unknown exception occurred during doWrite");
    Stop();
  }
}

void WebsocketClient::onWrite(boost::beast::error_code ec, std::size_t) {
  if (ec) {
    return Fail(ec, "onWrite");
  }

  if (running_ && was_connected_) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress identicalInnerCondition
    if (running_) {      // Double-check after acquiring lock
      out_queue_.pop();  // remove written item
      if (!out_queue_.empty() && running_) {
        DoWrite();  // send next message
      }
    }
  }
}

bool WebsocketClient::IsStarted() { return running_ && was_connected_; }
