/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/websocket/websocket_client.h"

#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(bui

#include "fptn-protocol-lib/https/https_client.h"
#include "fptn-protocol-lib/protobuf/protocol.h"

using fptn::protocol::websocket::WebsocketClient;

WebsocketClient::WebsocketClient(pcpp::IPv4Address server_ip,
    int server_port,
    pcpp::IPv4Address tun_interface_address_ipv4,
    pcpp::IPv6Address tun_interface_address_ipv6,
    NewIPPacketCallback new_ip_pkt_callback,
    std::string sni,
    std::string token)
    : ctx_(fptn::protocol::https::HttpsClient::CreateNewSslCtx()),
      resolver_(boost::asio::make_strand(ioc_)),
      ws_(boost::asio::make_strand(ioc_), ctx_),
      strand_(ioc_.get_executor()),
      running_(false),
      server_ip_(std::move(server_ip)),
      server_port_(server_port),
      tun_interface_address_ipv4_(std::move(tun_interface_address_ipv4)),
      tun_interface_address_ipv6_(std::move(tun_interface_address_ipv6)),
      new_ip_pkt_callback_(std::move(new_ip_pkt_callback)),
      sni_(std::move(sni)),
      token_(std::move(token)) {
  //  SPDLOG_INFO("Init new connection: {}:{}", server_ip_.toString(),
  //  server_port);

  fptn::protocol::https::HttpsClient::SetHandshakeSni(
      ws_.next_layer().native_handle(), sni_);
  fptn::protocol::https::HttpsClient::SetHandshakeSessionID(
      ws_.next_layer().native_handle());
  ctx_.set_verify_mode(boost::asio::ssl::verify_none);
}

void WebsocketClient::Run() {
  const std::string port_str = std::to_string(server_port_);
  auto self = shared_from_this();
  resolver_.async_resolve(server_ip_.toString(), port_str,
      [self](boost::beast::error_code ec,
          boost::asio::ip::tcp::resolver::results_type results) {
        if (ec) {
          SPDLOG_ERROR("Resolve error: {}", ec.message());
        } else {
          self->onResolve(ec, std::move(results));
        }
      });
  if (ioc_.stopped()) {
    ioc_.restart();
  }
  ioc_.run();
  running_ = false;
}

bool WebsocketClient::Stop() {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  running_ = false;

  try {
    boost::beast::get_lowest_layer(ws_).cancel();
    if (ws_.is_open()) {
      boost::beast::error_code ec;
      ws_.close(boost::beast::websocket::close_code::normal, ec);
      //      if (ec) {
      //        SPDLOG_ERROR("WebSocket sync close error: {}", ec.message());
      //      }
    }
    if (!ioc_.stopped()) {
      ioc_.stop();
    }
  } catch (const boost::system::system_error& err) {
    (void)err;
    //    SPDLOG_ERROR("Stop error: {}", err.what());
    if (!ioc_.stopped()) {
      ioc_.stop();
    }
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
  ws_.set_option(boost::beast::websocket::stream_base::decorator(
      [this](boost::beast::websocket::request_type& req) {
        // set browser headers
        using fptn::protocol::https::HttpsClient;
        const auto headers =
            HttpsClient::RealBrowserHeaders(sni_, server_port_);
        for (const auto& [key, value] : headers) {
          req.set(key, value);
        }
        // set custom headers
        req.set("Authorization", "Bearer " + token_);
        req.set("ClientIP", tun_interface_address_ipv4_.toString());
        req.set("ClientIPv6", tun_interface_address_ipv6_.toString());
        req.set("Client-Agent",
            fmt::format("FptnClient({}/{})", FPTN_USER_OS, FPTN_VERSION));
      }));

  // Perform the websocket handshake
  ws_.async_handshake(server_ip_.toString(), "/fptn",
      boost::beast::bind_front_handler(
          &WebsocketClient::onHandshake, shared_from_this()));
}

void WebsocketClient::onHandshake(boost::beast::error_code ec) {
  if (ec) {
    return Fail(ec, "onHandshake");
  }
  running_ = true;
  SPDLOG_INFO("WebSocket connection started successfully");
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
  if (ec == boost::asio::error::operation_aborted) {
    SPDLOG_ERROR("fail: {} {}", what, ec.what());
    Stop();
  } else {
    SPDLOG_ERROR("error: {} {}", what, ec.what());
  }
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
