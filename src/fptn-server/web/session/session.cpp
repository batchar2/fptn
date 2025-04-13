/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/session/session.h"

#include <atomic>
#include <memory>
#include <string>
#include <utility>

#include <boost/algorithm/string/replace.hpp>
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace {
std::atomic<fptn::ClientID> client_id = 0;
}

using fptn::web::Session;

Session::Session(boost::asio::ip::tcp::socket&& socket,
    boost::asio::ssl::context& ctx,
    const ApiHandleMap& api_handles,
    WebSocketOpenConnectionCallback ws_open_callback,
    WebSocketNewIPPacketCallback ws_new_ippacket_callback,
    WebSocketCloseConnectionCallback ws_close_callback)
    : ws_(std::move(socket), ctx),
      strand_(ws_.get_executor()),
      write_channel_(ws_.get_executor(), 256),
      api_handles_(api_handles),
      ws_open_callback_(std::move(ws_open_callback)),
      ws_new_ippacket_callback_(std::move(ws_new_ippacket_callback)),
      ws_close_callback_(std::move(ws_close_callback)),
      running_(false),
      init_completed_(false),
      full_queue_(false) {
  try {
    boost::beast::get_lowest_layer(ws_).socket().set_option(
        boost::asio::ip::tcp::no_delay(true));  // turn off the Nagle algorithm.

    ws_.text(false);
    ws_.binary(true);                  // Only binary
    ws_.auto_fragment(true);           // FIXME NEED CHECK
    ws_.read_message_max(128 * 1024);  // MaxSize (128 KB)
    ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
        boost::beast::role_type::server));
    ws_.set_option(boost::beast::websocket::stream_base::timeout{
        .handshake_timeout = std::chrono::seconds(60),  // Handshake timeout
        .idle_timeout = std::chrono::hours(24),         // Idle timeout
        .keep_alive_pings = true                        // Enable ping timeout
    });
    // Set a timeout to force reconnection every 2 hours
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(2));
    init_completed_ = true;
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Session::init error: {}", err.what());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Session::init prepare: {}", e.what());
  }
}

Session::~Session() { Close(); }

boost::asio::awaitable<void> Session::Run() {
  boost::system::error_code ec;

  // check init status
  if (!init_completed_) {
    SPDLOG_ERROR("Session is not initialized. Closing session.");
    Close();
    co_return;
  }

  // do handshake
  co_await ws_.next_layer().async_handshake(
      boost::asio::ssl::stream_base::server,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    SPDLOG_ERROR("Session handshake failed: {} ({})", ec.what(), ec.value());
    Close();
    co_return;
  }
  running_ = co_await ProcessRequest();
  if (running_) {
    auto self = shared_from_this();
    boost::asio::co_spawn(
        strand_,
        [self]() mutable -> boost::asio::awaitable<void> {
          return self->RunReader();
        },
        boost::asio::detached);
    boost::asio::co_spawn(
        strand_,
        [self]() mutable -> boost::asio::awaitable<void> {
          return self->RunSender();
        },
        boost::asio::detached);
  }
  co_return;
}

boost::asio::awaitable<void> Session::RunReader() {
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;
  while (running_) {
    try {
      // read
      co_await ws_.async_read(
          buffer, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (ec) {
        break;
      }
      // parse
      if (buffer.size() != 0) {
        std::string rawdata = boost::beast::buffers_to_string(buffer.data());
        std::string rawip = fptn::common::protobuf::protocol::GetProtoPayload(
            std::move(rawdata));
        auto packet = fptn::common::network::IPPacket::Parse(
            std::move(rawip), client_id_);
        if (packet != nullptr && ws_new_ippacket_callback_) {
          ws_new_ippacket_callback_(std::move(packet));
        }
        buffer.consume(buffer.size());  // flush
      }
    } catch (const fptn::common::protobuf::protocol::ProcessingError& err) {
      SPDLOG_ERROR("Session::runReader Processing error: {}", err.what());
    } catch (const fptn::common::protobuf::protocol::MessageError& err) {
      SPDLOG_ERROR("Session::runReader Message error: {}", err.what());
    } catch (const fptn::common::protobuf::protocol::UnsoportedProtocolVersion&
            err) {
      SPDLOG_ERROR(
          "Session::runReader Unsupported protocol version: {}", err.what());
    } catch (boost::system::system_error& err) {
      SPDLOG_ERROR("Session::runReader error: {}", err.what());
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Exception in runReader: {}", e.what());
    } catch (...) {
      SPDLOG_ERROR("Session::runReader Unexpected error");
      break;
    }
  }
  Close();
}

boost::asio::awaitable<void> Session::RunSender() {
  boost::system::error_code ec;

  auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);

  std::string msg;
  msg.reserve(4096);

  while (running_ && ws_.is_open()) {
    // read
    auto packet = co_await write_channel_.async_receive(token);
    if (!running_ || !write_channel_.is_open() || ec) {
      SPDLOG_ERROR("Session::runSender close, ec = {}", ec.value());
      break;
    }
    if (packet != nullptr) {
      // send
      msg = fptn::common::protobuf::protocol::CreateProtoPacket(
          std::move(packet));
      if (!msg.empty()) {
        co_await ws_.async_write(
            boost::asio::buffer(msg.data(), msg.size()), token);
        if (ec) {
          SPDLOG_ERROR("Session::runSender async_write error: {}", ec.what());
          break;
        }
        msg.clear();
      }
    }
  }
  co_return;
}

boost::asio::awaitable<bool> Session::ProcessRequest() {
  bool status = false;

  try {
    boost::system::error_code ec;
    boost::beast::flat_buffer buffer;
    boost::beast::http::request<boost::beast::http::string_body> request;

    co_await boost::beast::http::async_read(ws_.next_layer(), buffer, request,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    // FIXME check ec
    if (boost::beast::websocket::is_upgrade(request)) {
      status = co_await HandleWebSocket(request);
      if (status) {
        co_await ws_.async_accept(request,
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      }
    } else {
      status = co_await HandleHttp(request);
    }
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Session::handshake error: {}", err.what());
  }
  co_return status;
}

boost::asio::awaitable<bool> Session::HandleHttp(
    const boost::beast::http::request<boost::beast::http::string_body>&
        request) {
  const std::string url = request.target();
  const std::string method = request.method_string();

  if (method.empty() && url.empty()) {
    co_return false;
  }

  SPDLOG_INFO("HTTP {} {}", method, url);

  // default content types
  boost::beast::http::response<boost::beast::http::string_body> resp;
  resp.set(boost::beast::http::field::pragma, "no-cache");
  resp.set(boost::beast::http::field::server, "nginx/1.24.0");
  resp.set(boost::beast::http::field::connection, "keep-alive");
  resp.set(boost::beast::http::field::content_type, "text/html; charset=utf-8");
  resp.set(boost::beast::http::field::cache_control,
      "no-cache, no-store, must-revalidate");
  resp.set(boost::beast::http::field::expires, "Fri, 07 Jun 1974 04:00:00 GMT");
  resp.set("x_bitrix_composite", "Cache (200)");

  const ApiHandle handler = getApiHandle(api_handles_, url, method);
  if (handler) {
    int status = handler(request, resp);
    resp.result(status);
  } else {
    // Return 404 if no handler found
    resp.result(boost::beast::http::status::not_found);
    resp.body() = "404 Not Found";
  }
  resp.prepare_payload();

  auto res_ptr = std::make_shared<
      boost::beast::http::response<boost::beast::http::string_body>>(
      std::move(resp));
  try {
    co_await boost::beast::http::async_write(
        ws_.next_layer(), *res_ptr, boost::asio::use_awaitable);
  } catch (const boost::beast::system_error& e) {
    SPDLOG_ERROR("Error writing HTTP response: {}", e.what());
  }
  co_return false;
}

boost::asio::awaitable<bool> Session::HandleWebSocket(
    const boost::beast::http::request<boost::beast::http::string_body>&
        request) {
  if (request.find("Authorization") != request.end() &&
      request.find("ClientIP") != request.end()) {
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      client_id_ = client_id++;  // Increment the clientId after using it
    }
    std::string token = request["Authorization"];
    boost::replace_first(token, "Bearer ", "");  // clean token string

    const std::string client_vpn_ipv4_str = request["ClientIP"];
    const std::string client_ip_str = ws_.next_layer()
                                          .next_layer()
                                          .socket()
                                          .remote_endpoint()
                                          .address()
                                          .to_string();

    // Create IPv4Address objects
    const pcpp::IPv4Address client_ip(client_ip_str);
    const pcpp::IPv4Address client_vpn_ipv4(client_vpn_ipv4_str);

    const std::string client_vpn_ipv6_str =
        (request.find("ClientIPv6") != request.end()
                ? request["ClientIPv6"]
                : FPTN_CLIENT_DEFAULT_ADDRESS_IP6);  // default value
    const pcpp::IPv6Address client_vpn_ipv6(client_vpn_ipv6_str);
    // run
    const bool status =
        ws_open_callback_(client_id_, client_ip, client_vpn_ipv4,
            client_vpn_ipv6, shared_from_this(), request.target(), token);
    co_return status;
  }
  co_return false;
}

void Session::Close() {
  if (!running_) {
    return;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  running_ = false;
  write_channel_.close();
  try {
    boost::system::error_code ec;
    if (ws_.is_open()) {
      ws_.close(boost::beast::websocket::close_code::normal, ec);
    }
    auto& ssl = ws_.next_layer();
    if (ssl.native_handle()) {
      SSL_shutdown(ssl.native_handle());
    }

    auto& tcp = ssl.next_layer();
    if (tcp.socket().is_open()) {
      tcp.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      tcp.socket().close(ec);
    }
    if (client_id_ != MAX_CLIENT_ID && ws_close_callback_) {
      ws_close_callback_(client_id_);
    }
    SPDLOG_INFO("--- close successful {} ---", client_id_);
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Session::close error: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR("Session::close undefined error");
  }
}

boost::asio::awaitable<bool> Session::Send(
    fptn::common::network::IPPacketPtr packet) {
  try {
    if (running_ && write_channel_.is_open()) {
      const bool status = write_channel_.try_send(
          boost::system::error_code(), std::move(packet));
      if (status) {
        full_queue_ = false;
      } else if (!full_queue_) {
        // Log a warning only once when the queue first becomes full
        full_queue_ = true;
        spdlog::warn("Session::send the queue is full");
      }
    }
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR("Session::send error: {}", err.what());
    co_return false;
  }
  co_return true;
}
