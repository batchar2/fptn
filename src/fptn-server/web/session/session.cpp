/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/session/session.h"

#include <atomic>
#include <memory>
#include <string>
#include <tuple>
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

#include "fptn-protocol-lib/https/obfuscator/methods/none/none_obfuscator.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/protobuf/protocol.h"
#include "fptn-protocol-lib/time/time_provider.h"

namespace {
std::atomic<fptn::ClientID> client_id_counter = 0;

std::vector<std::string> GetServerIpAddresses() {
  static std::mutex ip_mutex;
  static std::vector<std::string> server_ips;

  const std::lock_guard<std::mutex> lock(ip_mutex);

  if (server_ips.empty()) {
    server_ips = fptn::common::network::GetServerIpAddresses();
  }
  return server_ips;
}

}  // namespace

namespace fptn::web {

Session::Session(std::uint16_t port,
    bool enable_detect_probing,
    boost::asio::ip::tcp::socket&& socket,
    boost::asio::ssl::context& ctx,
    const ApiHandleMap& api_handles,
    WebSocketOpenConnectionCallback ws_open_callback,
    WebSocketNewIPPacketCallback ws_new_ippacket_callback,
    WebSocketCloseConnectionCallback ws_close_callback,
    fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator)
    : port_(port),
      enable_detect_probing_(enable_detect_probing),
      ws_(ssl_stream_type(
          obfuscator_socket_type(tcp_stream_type(std::move(socket)),
              obfuscator
                  ? std::move(obfuscator)
                  : std::make_shared<
                        fptn::protocol::https::obfuscator::NoneObfuscator>()),
          ctx)),
      strand_(boost::asio::make_strand(ws_.get_executor())),
      write_channel_(strand_, 128),
      api_handles_(api_handles),
      ws_open_callback_(std::move(ws_open_callback)),
      ws_new_ippacket_callback_(std::move(ws_new_ippacket_callback)),
      ws_close_callback_(std::move(ws_close_callback)),
      running_(false),
      init_completed_(false),
      ws_session_was_opened_(false),
      full_queue_(false) {
  try {
    client_id_ = ++client_id_counter;

    boost::beast::get_lowest_layer(ws_).socket().set_option(
        boost::asio::ip::tcp::no_delay(true));

    ws_.text(false);
    ws_.binary(true);
    ws_.auto_fragment(true);
    ws_.read_message_max(128 * 1024);
    ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
        boost::beast::role_type::server));
    ws_.set_option(boost::beast::websocket::stream_base::timeout{
        .handshake_timeout = std::chrono::seconds(60),
        .idle_timeout = std::chrono::seconds(60),
        .keep_alive_pings = true});

    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(15));
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
  if (!init_completed_) {
    SPDLOG_ERROR("Session not initialized. Closing connection (client_id={})",
        client_id_);
    Close();
    co_return;
  }

  // Detect probing
  if (enable_detect_probing_) {
    const auto probing_result = co_await DetectProbing();
    if (probing_result.should_close) {
      SPDLOG_WARN(
          "Connection rejected during probing (client_id={})", client_id_);
      Close();
      co_return;
    }
    if (probing_result.is_probing) {
      SPDLOG_WARN(
          "Probing detected. Redirecting to proxy (client_id={}, SNI={}, "
          "port={})",
          client_id_, probing_result.sni, port_);
      co_await HandleProxy(probing_result.sni, port_);
      Close();
      co_return;
    } else {
      SPDLOG_INFO(
          "SESSION ID correct. Continue setup connection (client_id={}))",
          client_id_);
    }
  }

  // SSL handshake
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
  co_await ws_.next_layer().async_handshake(
      boost::asio::ssl::stream_base::server,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    SPDLOG_DEBUG(
        "SSL handshake failed (client_id={}): {}", client_id_, ec.message());
    Close();
    co_return;
  }

  // Process request (HTTP or WebSocket)
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
    Close();
  }
  co_return;
}

boost::asio::awaitable<Session::ProbingResult> Session::DetectProbing() {
  try {
    auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();

    // Peek data without consuming it
    std::array<std::uint8_t, 4096> buffer{};
    const std::size_t bytes_read =
        co_await tcp_socket.async_receive(boost::asio::buffer(buffer),
            boost::asio::socket_base::message_peek, boost::asio::use_awaitable);

    if (!bytes_read) {
      SPDLOG_ERROR("Peeked zero bytes from socket (client_id={})", client_id_);
      co_return ProbingResult{
          .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
    }

    if (!pcpp::SSLLayer::IsSSLMessage(
            0, 0, buffer.data(), buffer.size(), true)) {
      SPDLOG_ERROR(
          "Not an SSL message, closing connection (client_id={})", client_id_);
      co_return ProbingResult{
          .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
    }

    pcpp::SSLLayer* ssl_layer = pcpp::SSLLayer::createSSLMessage(
        buffer.data(), buffer.size(), nullptr, nullptr);
    if (!ssl_layer) {
      SPDLOG_ERROR(
          "Failed to create SSL layer from handshake data (client_id={})",
          client_id_);
      co_return ProbingResult{
          .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
    }

    const auto* handshake = dynamic_cast<pcpp::SSLHandshakeLayer*>(ssl_layer);
    if (!handshake) {
      SPDLOG_ERROR("Failed to cast to SSLHandshakeLayer");
      co_return ProbingResult{
          .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = true};
    }

    const auto* hello =
        // cppcheck-suppress nullPointerRedundantCheck
        handshake->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
    if (!hello) {
      SPDLOG_ERROR(
          "Failed to extract SSLClientHelloMessage from handshake "
          "(client_id={})",
          client_id_);
      co_return ProbingResult{
          .is_probing = true, .sni = FPTN_DEFAULT_SNI, .should_close = false};
    }

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

    if (sni != FPTN_DEFAULT_SNI) {
      const bool is_recursive_attempt = co_await IsSniSelfProxyAttempt(sni);
      if (is_recursive_attempt) {
        SPDLOG_WARN(
            "Detected recursive proxy attempt! Client: {}, SNI: {}, "
            "Redirecting to default SNI: {}",
            client_id_, sni, FPTN_DEFAULT_SNI);
        sni = FPTN_DEFAULT_SNI;
      }
    }

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

    if (!fptn::protocol::https::utils::IsFptnClientSessionID(
            session_id, session_len)) {
      SPDLOG_ERROR(
          "Session ID does not match FPTN client format (client_id={})",
          client_id_);
      co_return ProbingResult{
          .is_probing = true, .sni = sni, .should_close = false};
    }

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
  // ИСПРАВЛЕНО: доступ к TCP сокету через get_lowest_layer
  auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();
  boost::asio::ip::tcp::socket target_socket(
      co_await boost::asio::this_coro::executor);

  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(10));

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
          co_await from.async_read_some(boost::asio::buffer(buf),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec || buf[0] == 0) {
            break;
          }
          co_await boost::asio::async_write(to,
              boost::asio::buffer(buf.data(), buf.size()),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
          if (ec) {
            break;
          }
        }
        boost::system::error_code close_ec;
        from.close(close_ec);
      } catch (const boost::system::system_error& e) {
        SPDLOG_ERROR("Coroutine system error: {} [{}] (client_id={})", e.what(),
            e.code().message(), self->client_id_);
      }
      co_return;
    };

    auto [client_to_server_result, server_to_client_result, completion_status] =
        co_await boost::asio::experimental::make_parallel_group(
            boost::asio::co_spawn(co_await boost::asio::this_coro::executor,
                forward(tcp_socket, target_socket), boost::asio::deferred),
            boost::asio::co_spawn(co_await boost::asio::this_coro::executor,
                forward(target_socket, tcp_socket), boost::asio::deferred))
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

  try {
    tcp_socket.close();
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR(
        "Failed to close the socket after proxy completion (client_id={}): {} "
        "[{}]",
        client_id_, e.what(), e.code().message());
  }

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
    while (running_ && ws_.is_open()) {
      co_await ws_.async_read(buffer, token);

      if (ec) {
        if (ec != boost::beast::websocket::error::closed) {
          SPDLOG_DEBUG("WebSocket read error (client_id={}): {}", client_id_,
              ec.message());
        }
        break;
      }

      if (buffer.size() > 0) {
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
      }
      buffer.consume(buffer.size());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "RunReader exception (client_id={}): {}", client_id_, e.what());
  }

  Close();
  co_return;
}

boost::asio::awaitable<void> Session::RunSender() {
  try {
    while (running_ && ws_.is_open()) {
      auto [ec, packet] = co_await write_channel_.async_receive(
          boost::asio::bind_cancellation_slot(cancel_signal_.slot(),
              boost::asio::as_tuple(boost::asio::use_awaitable)));

      if (!running_ || !ws_.is_open() || ec) {
        break;
      }
      if (packet != nullptr) {
        std::string msg =
            fptn::protocol::protobuf::CreateProtoPayload(std::move(packet));
        if (!msg.empty()) {
          // co_await strand_.post(boost::asio::use_awaitable);
          co_await ws_.async_write(
              boost::asio::buffer(msg), boost::asio::use_awaitable);

          // co_await ws_.async_write(boost::asio::buffer(msg),
          //     boost::asio::bind_executor(strand_,
          //     boost::asio::use_awaitable));
          // co_await ws_.async_write(
          //     boost::asio::buffer(msg), boost::asio::use_awaitable);
          // co_await ws_.async_write(boost::asio::buffer(msg),
          //     boost::asio::bind_executor(strand_,
          //     boost::asio::use_awaitable));
          // co_await ws_.async_write(boost::asio::buffer(msg),
          //     boost::asio::bind_executor(strand_,
          //     boost::asio::use_awaitable));
        }
      }
    }
  } catch (const boost::system::system_error& err) {
    if (err.code() != boost::asio::error::operation_aborted &&
        err.code() != boost::beast::websocket::error::closed) {
      SPDLOG_ERROR(
          "RunSender error (client_id={}): {}", client_id_, err.what());
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "RunSender exception (client_id={}): {}", client_id_, e.what());
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
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(12));

  if (request.find("Authorization") != request.end() &&
      request.find("ClientIP") != request.end()) {
    std::string token = request["Authorization"];
    boost::replace_first(token, "Bearer ", "");

    const std::string client_vpn_ipv4_str = request["ClientIP"];

    boost::system::error_code ec;
    const std::string client_ip_str = boost::beast::get_lowest_layer(ws_)
                                          .socket()
                                          .remote_endpoint(ec)
                                          .address()
                                          .to_string();
    if (ec) {
      SPDLOG_ERROR("Failed to get remote endpoint: {}", ec.message());
      co_return false;
    }

    try {
      const pcpp::IPv4Address client_ip(client_ip_str);
      const pcpp::IPv4Address client_vpn_ipv4(client_vpn_ipv4_str);

      const std::string client_vpn_ipv6_str =
          (request.find("ClientIPv6") != request.end()
                  ? request["ClientIPv6"]
                  : FPTN_CLIENT_DEFAULT_ADDRESS_IP6);
      const pcpp::IPv6Address client_vpn_ipv6(client_vpn_ipv6_str);

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
      ws_.close(boost::beast::websocket::close_code::normal, ec);
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
  if (ws_.next_layer().native_handle()) {
    try {
      ::SSL_set_quiet_shutdown(ws_.next_layer().native_handle(), 1);
      ::SSL_shutdown(ws_.next_layer().native_handle());
      ws_.next_layer().shutdown(ec);
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

  if (boost::beast::get_lowest_layer(ws_).socket().is_open()) {
    boost::beast::get_lowest_layer(ws_).socket().close(ec);
  }

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

boost::asio::awaitable<bool> Session::Send(common::network::IPPacketPtr pkt) {
  auto self = shared_from_this();
  boost::asio::post(strand_, [self, pkt = std::move(pkt)]() mutable {
    if (self->running_ && self->write_channel_.is_open()) {
      const bool status = self->write_channel_.try_send(
          boost::system::error_code(), std::move(pkt));
      if (!status && !self->full_queue_) {
        self->full_queue_ = true;
        SPDLOG_WARN(
            "Session::send queue is full (client_id={})", self->client_id_);
      }
    }
  });
  co_return true;
}

};  // namespace fptn::web
