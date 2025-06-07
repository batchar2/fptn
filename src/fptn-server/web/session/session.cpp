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
#include <pcapplusplus/SSLHandshake.h>  // NOLINT(build/include_order)
#include <pcapplusplus/SSLLayer.h>      // NOLINT(build/include_order)
#include <spdlog/spdlog.h>              // NOLINT(build/include_order)

#include "fptn-protocol-lib/protobuf/protocol.h"
#include "fptn-protocol-lib/tls/tls.h"

namespace {
std::atomic<fptn::ClientID> client_id = 0;
}

using fptn::web::Session;

Session::Session(std::uint16_t port,
    bool enable_detect_probing,
    boost::asio::ip::tcp::socket&& socket,
    boost::asio::ssl::context& ctx,
    const ApiHandleMap& api_handles,
    WebSocketOpenConnectionCallback ws_open_callback,
    WebSocketNewIPPacketCallback ws_new_ippacket_callback,
    WebSocketCloseConnectionCallback ws_close_callback)
    : port_(port),
      enable_detect_probing_(enable_detect_probing),
      ws_(std::move(socket), ctx),
      strand_(ws_.get_executor()),
      write_channel_(ws_.get_executor(), 256),
      api_handles_(api_handles),
      ws_open_callback_(std::move(ws_open_callback)),
      ws_new_ippacket_callback_(std::move(ws_new_ippacket_callback)),
      ws_close_callback_(std::move(ws_close_callback)),
      running_(false),
      init_completed_(false),
      was_ws_session_opened_(false),
      full_queue_(false) {
  try {
    {
      const std::unique_lock<std::mutex> lock(mutex_);  // mutex

      client_id_ = client_id++;  // Increment the clientId after using it
    }

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
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Session::init failed (client_id={}): {} [{}]", client_id_,
        err.what(), err.code().message());
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "Session::init exception (client_id={}): {}", client_id_, e.what());
  }
}

Session::~Session() { Close(); }

boost::asio::awaitable<void> Session::Run() {
  boost::system::error_code ec;

  running_ = true;
  // check init status
  if (!init_completed_) {
    SPDLOG_ERROR("Session not initialized. Closing connection (client_id={})",
        client_id_);
    Close();
    co_return;
  }

  // Detect probing
  if (enable_detect_probing_) {
    SPDLOG_DEBUG("Probing detection enabled (client_id={})", client_id_);
    const auto probing_result = co_await DetectProbing();
    // Close connection
    if (probing_result.should_close) {
      SPDLOG_WARN(
          "Connection rejected during probing (client_id={})", client_id_);
      Close();  // close connection
      co_return;
    }
    // Run proxy
    if (probing_result.is_probing) {
      SPDLOG_INFO(
          "Probing detected. Redirecting to proxy "
          "(client_id={}, SNI={}, port={})",
          client_id_, probing_result.sni, port_);
      co_await HandleProxy(probing_result.sni, port_);
      Close();  // close connection
      co_return;
    } else {
      SPDLOG_ERROR(
          "SESSION ID correct. Continue setup connection (client_id={}))",
          client_id_);
    }
  }

  // Handshake
  co_await ws_.next_layer().async_handshake(
      boost::asio::ssl::stream_base::server,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    SPDLOG_DEBUG(
        "Probing check passed — continuing session setup (client_id={})",
        client_id_);
    Close();
    co_return;
  }

  // Run API or WebSocket
  const bool status = co_await ProcessRequest();
  if (status) {
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
  } else {
    Close();  // Close connection: probing failed, unexpected or HTTP request
  }
  co_return;
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
boost::asio::awaitable<Session::ProbingResult> Session::DetectProbing() {
  auto& socket = ws_.next_layer().next_layer().socket();
  // Peek data without consuming it from the socket buffer!!!
  // This allows inspection without affecting subsequent reads!!!
  std::array<std::uint8_t, 4096> buffer{};
  const std::size_t bytes_read =
      co_await socket.async_receive(boost::asio::buffer(buffer),
          boost::asio::socket_base::message_peek, boost::asio::use_awaitable);
  if (!bytes_read) {
    SPDLOG_ERROR("Peeked zero bytes from socket (client_id={})", client_id_);
    co_return ProbingResult{
        .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
  }
  // Check ssl
  if (!pcpp::SSLLayer::IsSSLMessage(0, 0, buffer.data(), buffer.size(), true)) {
    SPDLOG_ERROR(
        "Not an SSL message, closing connection (client_id={})", client_id_);
    co_return ProbingResult{
        .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
  }
  // Create SslLayer
  pcpp::SSLLayer* ssl_layer = pcpp::SSLLayer::createSSLMessage(
      buffer.data(), buffer.size(), nullptr, nullptr);
  if (!ssl_layer) {
    SPDLOG_ERROR(
        "Failed to create SSL layer from handshake data (client_id={})",
        client_id_);
    co_return ProbingResult{
        .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
  }

  // Check handshake
  // https://github.com/wiresock/ndisapi/blob/master/examples/cpp/pcapplusplus/pcapplusplus.cpp#L40
  const auto* handshake = dynamic_cast<pcpp::SSLHandshakeLayer*>(ssl_layer);
  if (!handshake) {
    SPDLOG_ERROR("Failed to cast to SSLHandshakeLayer");
    co_return ProbingResult{
        .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
  }

  // Get TTL-HELLO
  auto* hello =
      // cppcheck-suppress nullPointerRedundantCheck
      handshake->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
  if (!hello) {
    SPDLOG_ERROR(
        "Failed to extract SSLClientHelloMessage from handshake (client_id={})",
        client_id_);
    co_return ProbingResult{
        .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
  }

  // Check SNI
  auto* sni_ext =
      // cppcheck-suppress nullPointerRedundantCheck
      hello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
  std::string sni = FPTN_DEFAULT_SNI;
  if (sni_ext) {
    sni = sni_ext->getHostName();
  }

  // Get Session ID
  constexpr std::size_t kSessionLen = 32;
  std::size_t session_len = std::min(
      static_cast<std::uint8_t>(kSessionLen), hello->getSessionIDLength());
  if (session_len != kSessionLen) {
    SPDLOG_ERROR(
        "Invalid session ID length: expected {}, got {} (client_id={})",
        kSessionLen, session_len, client_id_);
    co_return ProbingResult{
        .is_probing = true, .sni = sni, .should_close = false};
  }
  std::uint8_t session_id[kSessionLen] = {0};
  std::memcpy(session_id, hello->getSessionID(), session_len);

  // Check Session ID
  if (!fptn::protocol::tls::IsFptnClientSessionID(session_id, session_len)) {
    SPDLOG_ERROR("Session ID does not match FPTN client format (client_id={})",
        client_id_);
    co_return ProbingResult{
        .is_probing = true, .sni = sni, .should_close = false};
  }
  // Is is a valid FPTN client
  co_return ProbingResult{
      .is_probing = false, .sni = sni, .should_close = false};
}

boost::asio::awaitable<bool> Session::HandleProxy(
    const std::string& sni, int port) {
  auto& socket = ws_.next_layer().next_layer();
  boost::asio::ip::tcp::socket target_socket(
      co_await boost::asio::this_coro::executor);

  try {
    boost::asio::ip::tcp::resolver resolver(
        co_await boost::asio::this_coro::executor);
    const std::string port_str = std::to_string(port);

    auto endpoints = co_await resolver.async_resolve(
        sni, port_str, boost::asio::use_awaitable);
    co_await boost::asio::async_connect(
        target_socket, endpoints, boost::asio::use_awaitable);

    auto ep = target_socket.local_endpoint();
    SPDLOG_INFO("Proxying {}:{} <-> {}:{} (client_id={})",
        ep.address().to_string(), ep.port(), sni, port_str, client_id_);

    auto self = shared_from_this();
    auto forward = [self](
                       auto& from, auto& to) -> boost::asio::awaitable<void> {
      try {
        boost::system::error_code ec;
        std::array<char, 8192> buf{};
        while (self->running_) {
          const auto n = co_await from.async_read_some(boost::asio::buffer(buf),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec || n == 0) {
            break;
          }
          co_await boost::asio::async_write(to,
              boost::asio::buffer(buf.data(), n),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            break;
          }
        }
        from.close();
      } catch (const boost::system::system_error& e) {
        SPDLOG_ERROR("Coroutine system error: {} [{}] (client_id={})", e.what(),
            e.code().message(), self->client_id_);
      }
      co_return;
    };

    // Launch both forwarding directions in parallel
    auto [client_to_server_result, server_to_client_result, completion_status] =
        co_await boost::asio::experimental::make_parallel_group(
            boost::asio::co_spawn(co_await boost::asio::this_coro::executor,
                forward(socket, target_socket), boost::asio::deferred),
            boost::asio::co_spawn(co_await boost::asio::this_coro::executor,
                forward(target_socket, socket), boost::asio::deferred))
            .async_wait(boost::asio::experimental::wait_for_all(),
                boost::asio::use_awaitable);

    (void)client_to_server_result;
    (void)server_to_client_result;
    (void)completion_status;
    socket.close();
    target_socket.close();

    co_return true;
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR("Proxy system error: {} [{}] (client_id={})", e.what(),
        e.code().message(), client_id_);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Proxy error (client_id={}): {} ", e.what(), client_id_);
  }
  co_return false;
}

boost::asio::awaitable<void> Session::RunReader() {
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;

  auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);
  while (running_) {
    try {
      // read
      co_await ws_.async_read(buffer, token);
      if (ec) {
        break;
      }
      // parse
      if (buffer.size() != 0) {
        std::string raw_data = boost::beast::buffers_to_string(buffer.data());
        std::string raw_ip =
            fptn::protocol::protobuf::GetProtoPayload(std::move(raw_data));
        auto packet = fptn::common::network::IPPacket::Parse(
            std::move(raw_ip), client_id_);
        if (packet != nullptr && ws_new_ippacket_callback_) {
          ws_new_ippacket_callback_(std::move(packet));
        }
        buffer.consume(buffer.size());  // flush
      }
    } catch (const fptn::protocol::protobuf::ProcessingError& err) {
      SPDLOG_ERROR(
          "Session::runReader failed to process message (client_id={}): {}",
          client_id_, err.what());
    } catch (const fptn::protocol::protobuf::MessageError& err) {
      SPDLOG_ERROR(
          "Session::runReader received invalid message (client_id={}): {}",
          client_id_, err.what());
    } catch (const fptn::protocol::protobuf::UnsupportedProtocolVersion& err) {
      SPDLOG_ERROR(
          "Session::runReader unsupported protocol version (client_id={}): {}",
          client_id_, err.what());
    } catch (const boost::system::system_error& err) {
      SPDLOG_ERROR("Session::runReader system error (client_id={}): {} [{}]",
          client_id_, err.what(), err.code().message());
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Session::runReader unexpected exception (client_id={}): {}",
          client_id_, e.what());
    } catch (...) {
      SPDLOG_ERROR(
          "Session::runReader unknown fatal error (client_id={})", client_id_);
      break;
    }
  }
  Close();
  co_return;
}

boost::asio::awaitable<void> Session::RunSender() {
  boost::system::error_code ec;

  auto token = boost::asio::bind_cancellation_slot(cancel_signal_.slot(),
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));

  std::string msg;
  msg.reserve(4096);

  while (running_ && ws_.is_open()) {
    // read
    auto packet = co_await write_channel_.async_receive(token);
    if (!running_ || !write_channel_.is_open() || ec) {
      break;
    }
    if (packet != nullptr) {
      // send
      msg = fptn::protocol::protobuf::CreateProtoPayload(std::move(packet));
      if (!msg.empty()) {
        co_await ws_.async_write(
            boost::asio::buffer(msg.data(), msg.size()), token);
        if (ec) {
          SPDLOG_ERROR(
              "Session::runSender async_write failed (client_id={}): {} [{}]",
              client_id_, ec.message(), ec.value());
          break;
        }
        msg.clear();
      }
    }
  }
  Close();
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
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Session::handshake failed (client_id={}): {} [{}]",
        client_id_, err.what(), err.code().message());
  }
  co_return status;
}

boost::asio::awaitable<bool> Session::HandleHttp(
    const boost::beast::http::request<boost::beast::http::string_body>&
        request) {
  const std::string url = request.target();
  const std::string method = request.method_string();

  if (method.empty() && url.empty()) {
    SPDLOG_WARN(
        "HTTP request has empty method or URL (client_id={}): method='{}', "
        "url='{}'",
        client_id_, method, url);
    co_return false;
  }
  SPDLOG_INFO("HTTP request (client_id={}): {} {}", client_id_, method, url);

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

  const ApiHandle handler = GetApiHandle(api_handles_, url, method);
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
    SPDLOG_ERROR("Failed to write HTTP response (client_id={}): {}", client_id_,
        e.what());
  }
  co_return false;
}

boost::asio::awaitable<bool> Session::HandleWebSocket(
    const boost::beast::http::request<boost::beast::http::string_body>&
        request) {
  if (request.find("Authorization") != request.end() &&
      request.find("ClientIP") != request.end()) {
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
    try {
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
      was_ws_session_opened_ = true;
      co_return status;
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("Session error (client_id={}): {}", client_id_, ex.what());
    }
  }
  co_return false;
}

void Session::Close() {
  if (!running_) {
    return;
  }
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // close coroutines
  running_ = false;
  // send signal to sender
  cancel_signal_.emit(boost::asio::cancellation_type::all);
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
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Session::close failed (client_id={}): {} [{}]", client_id_,
        err.what(), err.code().message());
  } catch (...) {
    SPDLOG_ERROR("Session::close unknown error (client_id={})", client_id_);
  }
  if (ws_close_callback_ && was_ws_session_opened_) {
    try {
      ws_close_callback_(client_id_);
    } catch (...) {
      SPDLOG_ERROR(
          "WebSocket close callback threw unknown exception (client_id={})",
          client_id_);
    }
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
        SPDLOG_WARN("Session::send queue is full (client_id={})", client_id_);
      }
    }
  } catch (boost::system::system_error& err) {
    SPDLOG_ERROR(
        "Session::send failed (client_id={}): {}", client_id_, err.what());
    co_return false;
  }
  co_return true;
}
