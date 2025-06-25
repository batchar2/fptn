/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/session/session.h"

#include <atomic>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

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

#include "common/network/utils.h"

#include "fptn-protocol-lib/protobuf/protocol.h"
#include "fptn-protocol-lib/time/time_provider.h"
#include "fptn-protocol-lib/tls/tls.h"

namespace {
std::atomic<fptn::ClientID> client_id_counter = 0;

std::vector<std::string> GetServerIpAddresses() {
  static std::mutex ip_mutex;
  static std::vector<std::string> server_ips;

  const std::lock_guard<std::mutex> lock(ip_mutex);  // mutex

  if (server_ips.empty()) {
    server_ips = fptn::common::network::GetServerIpAddresses();
  }
  return server_ips;
}

}  // namespace

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
      ws_session_was_opened_(false),
      full_queue_(false) {
  try {
    client_id_ = ++client_id_counter;  // atomic operation

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
        .idle_timeout = std::chrono::seconds(60),       // Idle timeout
        .keep_alive_pings = true                        // Enable ping timeout
    });
    // Set a timeout to force reconnection every 30 seconds
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
    init_completed_ = true;
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("Session::init failed (client_id={}): {} [{}]", client_id_,
        err.what(), err.code().message());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Session::init unexpected exception (client_id={}): {}",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Session::init unknown fatal error (client_id={})", client_id_);
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
      SPDLOG_WARN(
          "Probing detected. Redirecting to proxy "
          "(client_id={}, SNI={}, port={})",
          client_id_, probing_result.sni, port_);
      co_await HandleProxy(probing_result.sni, port_);
      Close();  // close connection
      co_return;
    } else {
      SPDLOG_INFO(
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
  try {
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
    if (!pcpp::SSLLayer::IsSSLMessage(
            0, 0, buffer.data(), buffer.size(), true)) {
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
          "Failed to extract SSLClientHelloMessage from handshake "
          "(client_id={})",
          client_id_);
      co_return ProbingResult{
          .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
    }

    // Set  SNI
    std::string sni = FPTN_DEFAULT_SNI;
    auto* sni_ext =
        // cppcheck-suppress nullPointerRedundantCheck
        hello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
    if (sni_ext) {
      std::string tls_sni = sni_ext->getHostName();
      if (!tls_sni.empty()) {
        sni = std::move(tls_sni);
      }
    }

    // Detect and prevent recursive proxying to the local server
    if (sni != FPTN_DEFAULT_SNI) {
      const bool is_recursive_attempt = co_await IsSniSelfProxyAttempt(sni);
      if (is_recursive_attempt) {
        SPDLOG_WARN(
            "Detected recursive proxy attempt! "
            "Client: {}, SNI: {}, Redirecting to default SNI: {}",
            client_id_, sni, FPTN_DEFAULT_SNI);
        sni = FPTN_DEFAULT_SNI;
      }
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
      SPDLOG_ERROR(
          "Session ID does not match FPTN client format (client_id={})",
          client_id_);
      co_return ProbingResult{
          .is_probing = true, .sni = sni, .should_close = false};
    }
    // Valid FPTN client
    co_return ProbingResult{
        .is_probing = false, .sni = sni, .should_close = false};
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR(
        "System error during probing: {} (client_id={})", e.what(), client_id_);
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "Exception during probing: {} (client_id={})", e.what(), client_id_);
  } catch (...) {
    SPDLOG_ERROR("Unknown exception during probing (client_id={})", client_id_);
  }
  co_return ProbingResult{
      .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
boost::asio::awaitable<bool> Session::IsSniSelfProxyAttempt(
    const std::string& sni) const {
  // First check if SNI is already an IP address
  boost::system::error_code ec;
  boost::asio::ip::make_address(sni, ec);
  if (!ec) {
    // SNI is a valid IP address - check directly
    const auto server_ips = GetServerIpAddresses();
    // NOLINTNEXTLINE(modernize-use-ranges)
    const auto exists = std::find(server_ips.begin(), server_ips.end(), sni);
    co_return exists != server_ips.end();
  }

  // Not an IP address - proceed with DNS resolution
  boost::asio::ip::tcp::resolver resolver(
      co_await boost::asio::this_coro::executor);
  try {
    const auto server_ips = GetServerIpAddresses();

    const auto endpoints =
        co_await resolver.async_resolve(sni, "", boost::asio::use_awaitable);
    for (const auto& endpoint : endpoints) {
      const auto ip = endpoint.endpoint().address().to_string();
      // NOLINTNEXTLINE(modernize-use-ranges)
      const auto exists = std::find(server_ips.begin(), server_ips.end(), ip);
      if (exists != server_ips.end()) {
        co_return true;
      }
    }
  } catch (const boost::system::system_error& e) {
    SPDLOG_WARN("DNS resolution failed for {}: {}", sni, e.what());
    co_return true;
  } catch (...) {
    SPDLOG_WARN("Unknown error during DNS resolution for {}", sni);
    co_return true;
  }
  co_return false;
}

boost::asio::awaitable<bool> Session::HandleProxy(
    const std::string& sni, int port) {
  auto& socket = ws_.next_layer().next_layer();
  boost::asio::ip::tcp::socket target_socket(
      co_await boost::asio::this_coro::executor);

  // SET TTL
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(20));
  boost::beast::get_lowest_layer(socket).expires_after(
      std::chrono::seconds(20));

  bool status = false;
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
    status = true;
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR("Proxy system error: {} [{}] (client_id={})", e.what(),
        e.code().message(), client_id_);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Proxy error (client_id={}): {} ", e.what(), client_id_);
  }

  // close socket
  try {
    socket.close();
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR(
        "Failed to close the socket after proxy completion (client_id={}): "
        "{} "
        "[{}]",
        client_id_, e.what(), e.code().message());
  }
  // close target socket
  boost::system::error_code ec;
  target_socket.close(ec);

  SPDLOG_INFO("Close proxy (client_id={})", client_id_);

  co_return status;
}

boost::asio::awaitable<void> Session::RunReader() {
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;

  auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);
  try {
    while (running_) {
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
        if (!raw_ip.empty()) {
          auto packet = fptn::common::network::IPPacket::Parse(
              std::move(raw_ip), client_id_);
          if (packet != nullptr && ws_new_ippacket_callback_) {
            ws_new_ippacket_callback_(std::move(packet));
          }
        }
        buffer.consume(buffer.size());  // flush
      }
    }
  } catch (const fptn::protocol::protobuf::ProcessingError& err) {
    SPDLOG_ERROR(
        "RunReader: failed to process protobuf payload (client_id={}): {}",
        client_id_, err.what());
  } catch (const fptn::protocol::protobuf::MessageError& err) {
    SPDLOG_ERROR(
        "RunReader: received invalid protobuf message (client_id={}): {}",
        client_id_, err.what());
  } catch (const fptn::protocol::protobuf::UnsupportedProtocolVersion& err) {
    SPDLOG_ERROR("RunReader: unsupported protocol version (client_id={}): {}",
        client_id_, err.what());
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("RunReader: Boost system error (client_id={}): {} [code={}]",
        client_id_, err.what(), err.code().value());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunReader: unexpected exception (client_id={}): {}",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR("RunReader: unknown fatal error (client_id={})", client_id_);
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

  try {
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
                "RunSender: failed to send packet (client_id={}): {} [code={}]",
                client_id_, ec.message(), ec.value());
            break;
          }
          msg.clear();
        }
      }
    }
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR("RunSender: Boost system error (client_id={}): {} [code={}]",
        client_id_, err.what(), err.code().value());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("RunSender: unhandled exception (client_id={}): {}",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR("RunSender: unknown fatal error (client_id={})", client_id_);
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

  // control TTL socket
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

  if (method.empty() && url.empty()) {
    SPDLOG_WARN(
        "HTTP request has empty method or URL (client_id={}): method='{}', "
        "url='{}'",
        client_id_, method, url);
    co_return false;
  }

  if (url.find("metrics") == std::string::npos) {  // NOLINT
    SPDLOG_INFO("HTTP request (client_id={}): {} {}", client_id_, method, url);
  } else {
    SPDLOG_INFO("HTTP request (client_id={}): {} {}", client_id_, method,
        "/api/v1/metrics/<hidden>");
  }

  const auto server_info = fmt::format("fptn/{}", FPTN_VERSION);
  const auto http_date = fptn::time::TimeProvider::Instance()->Rfc7231Date();

  // set content types
  boost::beast::http::response<boost::beast::http::string_body> resp;
  resp.set(boost::beast::http::field::server, server_info);
  resp.set(boost::beast::http::field::content_type,
      "application/json; charset=utf-8");
  resp.set(boost::beast::http::field::cache_control,
      "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0");
  resp.set(boost::beast::http::field::pragma, "no-cache");
  resp.set(boost::beast::http::field::expires, "0");
  resp.set(boost::beast::http::field::date, http_date);

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
    SPDLOG_ERROR("Session::HandleHttp write error (client_id={}): {}",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Session::HandleHttp write unknown error (client_id={})", client_id_);
  }
  co_return false;
}

boost::asio::awaitable<bool> Session::HandleWebSocket(
    const boost::beast::http::request<boost::beast::http::string_body>&
        request) {
  // Set a long expiration timeout (7 days) to avoid disconnects
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(24 * 7));

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
      ws_session_was_opened_ = true;
      co_return status;
    } catch (const std::exception& ex) {
      SPDLOG_ERROR(
          "Session::Open (client_id={}): Exception caught while creating IP "
          "addresses or running callback: {}",
          client_id_, ex.what());
    } catch (...) {
      SPDLOG_ERROR(
          "Session::Open (client_id={}): Unknown fatal error caught while "
          "creating IP addresses or running callback",
          client_id_);
    }
  }
  co_return false;
}

void Session::Close() {
  if (!running_) {
    return;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // cppcheck-suppress identicalConditionAfterEarlyExit
  if (!running_) {  // Double-check after acquiring lock
    return;
  }

  running_ = false;
  boost::system::error_code ec;

  // Cancel ongoing operations
  try {
    cancel_signal_.emit(boost::asio::cancellation_type::all);
    write_channel_.close();
  } catch (const std::exception& err) {
    SPDLOG_ERROR(
        "Failed to cancel session or close write_channel: {}", err.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Session::shutdown unknown fatal error (client_id={})", client_id_);
  }

  // Close WebSocket
  if (ws_.is_open()) {
    try {
      boost::beast::get_lowest_layer(ws_).expires_after(
          std::chrono::microseconds(1));
    } catch (const std::exception& err) {
      SPDLOG_ERROR(
          "Session::Close (client_id={}): Failed to set socket timeout using "
          "expires_after: {}",
          client_id_, err.what());
    } catch (...) {
      SPDLOG_ERROR(
          "Session::Close (client_id={}): Unknown error occurred while setting "
          "socket timeout with expires_after",
          client_id_);
    }
  }

  try {
    if (ws_.is_open()) {
      ws_.async_close(boost::beast::websocket::close_code::normal,
          [](const boost::system::error_code&) {});
    }
  } catch (const std::exception& err) {
    SPDLOG_ERROR(
        "Session::Close (client_id={}): Exception during async_close: {}",
        client_id_, err.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Session::Close (client_id={}): Unknown error during async_close",
        client_id_);
  }

  // Close SSL
  auto& ssl = ws_.next_layer();
  if (ssl.native_handle()) {
    try {
      // More robust SSL shutdown
      ::SSL_set_quiet_shutdown(ssl.native_handle(), 1);
      ::SSL_shutdown(ssl.native_handle());
      ssl.shutdown(ec);
      ssl.lowest_layer().close(ec);
    } catch (const std::exception& err) {
      SPDLOG_ERROR(
          "Session::Close (client_id={}): Exception during SSL_shutdown: {}",
          client_id_, err.what());
    } catch (...) {
      SPDLOG_ERROR(
          "Session::Close (client_id={}): Unknown error during SSL_shutdown",
          client_id_);
    }
  }

  // Close TCP
  auto& tcp = ssl.next_layer();
  if (tcp.socket().is_open()) {
    tcp.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    tcp.socket().close(ec);
  }

  // Call close callback
  if (ws_close_callback_ && ws_session_was_opened_) {
    try {
      ws_close_callback_(client_id_);
    } catch (const std::exception& e) {
      SPDLOG_ERROR(
          "WebSocket close callback threw exception (client_id={}): {}",
          client_id_, e.what());
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
    co_return true;
  } catch (const boost::system::system_error& err) {
    SPDLOG_ERROR(
        "Session::Send failed (client_id={}): {}", client_id_, err.what());
  } catch (const std::exception& ex) {
    SPDLOG_ERROR("Session::Send unexpected exception (client_id={}): {}",
        client_id_, ex.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Session::Send unknown fatal error (client_id={})", client_id_);
  }
  co_return false;
}
