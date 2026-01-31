/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/client_endpoint/client_endpoint.h"

#include <atomic>
#include <memory>
#include <string>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

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

#include "common/network/resolv.h"
#include "common/network/utils.h"

#include "fptn-protocol-lib/https/obfuscator/methods/detector.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"
#include "fptn-protocol-lib/protobuf/protocol.h"
#include "fptn-protocol-lib/time/time_provider.h"
#include "fptn-server/nat/connect_params.h"
#include "nat/connect_params.h"

namespace {
std::atomic<fptn::ClientID> client_id_counter = 0;

std::vector<std::string> GetServerIpAddresses(
    const std::string& server_external_ips) {
  static std::mutex ip_mutex;
  static std::vector<std::string> server_ips;

  const std::scoped_lock lock(ip_mutex);  // mutex

  if (server_ips.empty()) {
    server_ips = fptn::common::network::GetServerIpAddresses();

    if (!server_external_ips.empty()) {
      const auto external_ips =
          fptn::common::utils::SplitCommaSeparated(server_external_ips);
      std::ranges::copy_if(external_ips, std::back_inserter(server_ips),
          [](const std::string& ip) {
            return fptn::common::network::IsIpAddress(ip);
          });
    }
  }
  return server_ips;
}

void SetSocketTimeouts(boost::asio::ip::tcp::socket& socket, int timeout_sec) {
  timeval tv = {};
  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;
  const int socket_fd = socket.native_handle();
  ::setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
      reinterpret_cast<const char*>(&tv), sizeof(tv));
  ::setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO,
      reinterpret_cast<const char*>(&tv), sizeof(tv));
}

std::uint64_t ParseRequestUint(
    const boost::beast::http::request<boost::beast::http::string_body>& request,
    const std::string& param_name,
    const std::uint64_t default_value = UINT64_MAX) {
  if (request.contains(param_name)) {
    const std::string value_str =
        fptn::common::utils::FilterDigitsOnly(request[param_name]);
    if (value_str.empty()) {
      return default_value;
    }
    try {
      std::size_t pos = 0;
      const std::uint64_t value = std::stoull(value_str, &pos, 10);
      if (pos != value_str.size()) {
        return default_value;
      }
      return value;
    } catch (const std::exception&) {
      return default_value;
    }
  }
  return default_value;
}

std::string ParseRequestStr(
    const boost::beast::http::request<boost::beast::http::string_body>& request,
    const std::string& param_name,
    const std::string& default_value) {
  if (request.contains(param_name)) {
    return request[param_name];
  }
  return default_value;
}

}  // namespace

namespace fptn::web {

ClientEndpoint::ClientEndpoint(std::uint16_t port,
    bool enable_detect_probing,
    std::string default_proxy_domain,
    std::vector<std::string> allowed_sni_list,
    std::string server_external_ips,
    boost::asio::ip::tcp::socket&& socket,
    boost::asio::ssl::context& ctx,
    const ApiHandleMap& api_handles,
    HandshakeCacheManagerSPtr handshake_cache_manager,
    WebSocketOpenConnectionCallback ws_open_callback,
    WebSocketNewIPPacketCallback ws_new_ippacket_callback,
    WebSocketCloseConnectionCallback ws_close_callback)
    : port_(port),
      enable_detect_probing_(enable_detect_probing),
      default_proxy_domain_(std::move(default_proxy_domain)),
      allowed_sni_list_(std::move(allowed_sni_list)),
      server_external_ips_(std::move(server_external_ips)),
      ws_(ssl_stream_type(
          obfuscator_socket_type(tcp_stream_type(std::move(socket))), ctx)),
      strand_(boost::asio::make_strand(ws_.get_executor())),
      write_channel_(strand_, 128),
      api_handles_(api_handles),
      handshake_cache_manager_(std::move(handshake_cache_manager)),
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
    SPDLOG_ERROR("ClientEndpoint::init failed (client_id={}): {} [{}]",
        client_id_, err.what(), err.code().message());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("ClientEndpoint::init unexpected exception (client_id={}): {}",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR(
        "ClientEndpoint::init unknown fatal error (client_id={})", client_id_);
  }
}

ClientEndpoint::~ClientEndpoint() { Close(); }

boost::asio::awaitable<void> ClientEndpoint::Run() {
  boost::system::error_code ec;

  running_ = true;
  if (!init_completed_) {
    SPDLOG_ERROR(
        "ClientEndpoint not initialized. Closing connection (client_id={})",
        client_id_);
    Close();
    co_return;
  }

  // Setup traffic obfuscator
  auto obfuscator_opt = co_await DetectObfuscator();
  if (!obfuscator_opt.has_value()) {
    SPDLOG_ERROR("Failed to initialize traffic obfuscator");
    Close();
    co_return;
  }
  ws_.next_layer().next_layer().set_obfuscator(obfuscator_opt.value());

  // Detect probing (only for null obfuscator)
  if (enable_detect_probing_ && obfuscator_opt.value() == nullptr) {
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
    }
    SPDLOG_INFO("SESSION ID correct. Continue setup connection (client_id={})",
        client_id_);
  }

  // Check for Reality Mode handshake (only when no obfuscator is detected)
  if (obfuscator_opt.value() == nullptr) {
    const auto result = co_await IsRealityHandshake();
    if (result.should_close) {
      SPDLOG_WARN(
          "Reality Mode handshake check failed (client_id={})", client_id_);
      Close();
      co_return;
    }

    // Process Reality Mode connection if detected
    if (result.is_reality_mode) {
      SPDLOG_INFO("Processing Reality Mode connection sni={} (client_id={}) ",
          result.sni, client_id_);

      // Prevent recursive proxy attempts for Reality Mode
      const auto self_proxy = co_await IsSniSelfProxyAttempt(result.sni);
      if (self_proxy) {
        co_await HandleProxy(default_proxy_domain_, port_);
        Close();
        co_return;
      }

      const bool reality_success = co_await HandleRealityMode(result.sni);
      if (!reality_success) {
        SPDLOG_WARN("Reality mode handshake failed (client_id={})", client_id_);
        Close();
        co_return;
      }
      // For Reality Mode we use TLS obfuscator after fake handshake
      // This provides additional encryption layer for the real connection
      ws_.next_layer().next_layer().set_obfuscator(
          std::make_shared<protocol::https::obfuscator::TlsObfuscator>());
    }
  }
  // SSL handshake
  boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(10));
  co_await ws_.next_layer().async_handshake(
      boost::asio::ssl::stream_base::server,
      boost::asio::redirect_error(boost::asio::use_awaitable, ec));
  if (ec) {
    SPDLOG_WARN("TLS-Handshake error (client_id={})", client_id_);
    Close();
    co_return;
  }

  // Reset obfuscator after TLS handshake
  ws_.next_layer().next_layer().set_obfuscator(nullptr);

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

boost::asio::awaitable<ClientEndpoint::ProbingResult>
ClientEndpoint::DetectProbing() {
  try {
    auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();
    // Peek data without consuming it from the socket buffer!!!
    // This allows inspection without affecting subsequent reads!!!
    std::array<std::uint8_t, 16384> buffer{};
    const std::size_t bytes_read =
        co_await tcp_socket.async_receive(boost::asio::buffer(buffer),
            boost::asio::socket_base::message_peek, boost::asio::use_awaitable);
    if (!bytes_read) {
      SPDLOG_ERROR("Peeked zero bytes from socket (client_id={})", client_id_);
      co_return ProbingResult{.is_probing = true,
          .sni = default_proxy_domain_,
          .should_close = true};
    }
    // Check ssl
    if (!pcpp::SSLLayer::IsSSLMessage(
            0, 0, buffer.data(), buffer.size(), true)) {
      SPDLOG_ERROR(
          "Not an SSL message, closing connection (client_id={})", client_id_);
      co_return ProbingResult{.is_probing = true,
          .sni = default_proxy_domain_,
          .should_close = true};
    }
    // Create SslLayer
    pcpp::SSLLayer* ssl_layer = pcpp::SSLLayer::createSSLMessage(
        buffer.data(), buffer.size(), nullptr, nullptr);
    if (!ssl_layer) {
      SPDLOG_ERROR(
          "Failed to create SSL layer from handshake data (client_id={})",
          client_id_);
      co_return ProbingResult{.is_probing = true,
          .sni = default_proxy_domain_,
          .should_close = true};
    }

    // Check handshake
    // https://github.com/wiresock/ndisapi/blob/master/examples/cpp/pcapplusplus/pcapplusplus.cpp#L40
    const auto* handshake = dynamic_cast<pcpp::SSLHandshakeLayer*>(ssl_layer);
    if (!handshake) {
      SPDLOG_ERROR("Failed to cast to SSLHandshakeLayer");
      co_return ProbingResult{.is_probing = true,
          .sni = default_proxy_domain_,
          .should_close = true};
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
      co_return ProbingResult{.is_probing = true,
          .sni = default_proxy_domain_,
          .should_close = true};
    }

    // Set  SNI
    std::string sni = default_proxy_domain_;
    auto* sni_ext =
        // cppcheck-suppress nullPointerRedundantCheck
        hello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
    if (sni_ext) {
      std::string tls_sni = sni_ext->getHostName();
      if (!tls_sni.empty()) {
        sni = std::move(tls_sni);
      }
    }
    // Validate allowed sni
    if (!allowed_sni_list_.empty()) {
      const bool sni_allowed = std::ranges::any_of(
          allowed_sni_list_, [&sni](const std::string& allowed_sni) {
            if (sni == allowed_sni) {
              return true;
            }
            // check subdomains
            if (sni.size() > allowed_sni.size() + 1) {
              return sni.ends_with("." + allowed_sni);
            }
            return false;
          });
      if (!sni_allowed) {
        sni = default_proxy_domain_;
        SPDLOG_WARN(
            "SNI '{}' not in allowed list, using default domain: {} "
            "(client_id={})",
            sni, default_proxy_domain_, client_id_);
      }
    }

    // Detect and prevent recursive proxying to the local server
    if (sni != default_proxy_domain_) {
      const bool is_recursive_attempt = co_await IsSniSelfProxyAttempt(sni);
      if (is_recursive_attempt) {
        SPDLOG_WARN(
            "Detected recursive proxy attempt! "
            "Client: {}, SNI: {}, Redirecting to default SNI: {}",
            client_id_, sni, default_proxy_domain_);
        sni = default_proxy_domain_;
      }
    }

    // Get ClientEndpoint ID
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

    // Check ClientEndpoint ID
    const bool is_fptn_session_id =
        protocol::https::utils::IsFptnClientSessionID(session_id, session_len);
    const bool is_decoy_session_id =
        protocol::https::utils::IsDecoyHandshakeSessionID(
            session_id, session_len);
    if (!is_fptn_session_id && !is_decoy_session_id) {
      SPDLOG_ERROR(
          "ClientEndpoint ID does not match FPTN client format (client_id={})",
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
      .is_probing = true, .sni = default_proxy_domain_, .should_close = true};
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
boost::asio::awaitable<bool> ClientEndpoint::IsSniSelfProxyAttempt(
    const std::string& sni) const {
  // First check if SNI is already an IP address
  if (fptn::common::network::IsIpAddress(sni)) {
    // FIXME
    SPDLOG_WARN("SNI is IP address, treating as potential self-proxy: {}", sni);
    co_return true;
  }

  // Not an IP address - proceed with DNS resolution using our new function
  try {
    const auto server_ips = GetServerIpAddresses(server_external_ips_);

    boost::asio::io_context ioc;
    const auto resolve_result =
        fptn::common::network::ResolveWithTimeout(ioc, sni, "", 5);

    if (!resolve_result.success()) {
      SPDLOG_WARN("DNS resolution failed for {}: {}", sni,
          resolve_result.error.message());
      co_return true;  // Treat DNS failure as potential self-proxy attempt
    }

    // Iterate through resolved endpoints
    for (const auto& endpoint : resolve_result.results) {
      const auto ip = endpoint.endpoint().address().to_string();
      if (ip.empty()) {
        continue;
      }
      // check server interfaces
      if (std::ranges::find(server_ips, ip) != server_ips.end()) {
        SPDLOG_WARN(
            "SNI {} resolves to server interface IP {}, blocking self-proxy",
            sni, ip);
        co_return true;
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_WARN("Exception during DNS resolution for {}: {}", sni, e.what());
    co_return true;
  }

  co_return false;
}

boost::asio::awaitable<ClientEndpoint::RealityResult>
ClientEndpoint::IsRealityHandshake() {
  try {
    auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();

    // Peek data without consuming it
    std::array<std::uint8_t, 16384> buffer{};
    const std::size_t bytes_read =
        co_await tcp_socket.async_receive(boost::asio::buffer(buffer),
            boost::asio::socket_base::message_peek, boost::asio::use_awaitable);

    if (!bytes_read) {
      co_return RealityResult{
          .is_reality_mode = false, .sni = "", .should_close = true};
    }

    // Check if it's SSL/TLS handshake
    if (!pcpp::SSLLayer::IsSSLMessage(
            0, 0, buffer.data(), buffer.size(), true)) {
      co_return RealityResult{
          .is_reality_mode = false, .sni = "", .should_close = true};
    }

    // Parse SSL handshake
    pcpp::SSLLayer* ssl_layer = pcpp::SSLLayer::createSSLMessage(
        buffer.data(), buffer.size(), nullptr, nullptr);
    if (!ssl_layer) {
      co_return RealityResult{
          .is_reality_mode = false, .sni = "", .should_close = true};
    }

    // Check handshake
    // https://github.com/wiresock/ndisapi/blob/master/examples/cpp/pcapplusplus/pcapplusplus.cpp#L40
    auto* handshake = dynamic_cast<pcpp::SSLHandshakeLayer*>(ssl_layer);
    if (!handshake) {
      co_return RealityResult{
          .is_reality_mode = false, .sni = "", .should_close = true};
    }

    auto* hello =
        // cppcheck-suppress nullPointerRedundantCheck
        handshake->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
    if (!hello) {
      co_return RealityResult{
          .is_reality_mode = false, .sni = "", .should_close = true};
    }

    // Get SNI
    std::string sni = default_proxy_domain_;
    auto* sni_ext =
        // cppcheck-suppress nullPointerRedundantCheck
        hello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
    if (sni_ext) {
      std::string tls_sni = sni_ext->getHostName();
      if (!tls_sni.empty()) {
        sni = std::move(tls_sni);
      }
    }

    // Check if this is a reality mode handshake by examining session ID
    constexpr std::size_t kSessionLen = 32;
    std::size_t session_len = std::min(
        static_cast<std::uint8_t>(kSessionLen), hello->getSessionIDLength());

    if (session_len == kSessionLen) {
      std::uint8_t session_id[kSessionLen] = {0};
      std::memcpy(session_id, hello->getSessionID(), session_len);

      // Check if it's a decoy handshake (reality mode)
      if (protocol::https::utils::IsDecoyHandshakeSessionID(
              session_id, session_len)) {
        co_return RealityResult{
            .is_reality_mode = true, .sni = sni, .should_close = false};
      }
      co_return RealityResult{
          .is_reality_mode = false, .sni = sni, .should_close = false};
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("IsRealityHandshake exception (client_id={}): {}", client_id_,
        e.what());
  }
  co_return RealityResult{
      .is_reality_mode = true, .sni = "", .should_close = true};
}

boost::asio::awaitable<bool> ClientEndpoint::HandleRealityMode(
    const std::string& sni) {
  try {
    auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();

    std::vector<std::uint8_t> buffer(16384, '\0');
    // std::string buffer(16384, '\0');
    const std::size_t bytes_read = co_await tcp_socket.async_receive(
        boost::asio::buffer(buffer), boost::asio::use_awaitable);
    if (!bytes_read || !handshake_cache_manager_) {
      co_return false;
    }
    buffer.resize(bytes_read);

    const auto handshake_answer =
        co_await handshake_cache_manager_->GetHandshake(
            sni, buffer.data(), bytes_read, std::chrono::seconds(3));

    if (!handshake_answer) {
      co_return false;
    }

    const std::size_t bytes_wrote =
        co_await boost::asio::async_write(tcp_socket,
            boost::asio::buffer(*handshake_answer), boost::asio::use_awaitable);

    SPDLOG_INFO(
        "Reality mode completed, ready for real handshake (client_id={}) "
        "request_size = {} response_size: {}",
        client_id_, bytes_read, bytes_wrote);
    co_return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "HandleRealityMode exception (client_id={}): {}", client_id_, e.what());
  }
  co_return false;
}

boost::asio::awaitable<bool> ClientEndpoint::HandleProxy(
    const std::string& sni, int port) {
  auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();
  boost::asio::ip::tcp::socket target_socket(
      co_await boost::asio::this_coro::executor);

  constexpr int kTimeout = 10;
  boost::beast::get_lowest_layer(ws_).expires_after(
      std::chrono::seconds(kTimeout));

  bool status = false;
  try {
    const std::string port_str = std::to_string(port);

    boost::asio::io_context ioc;
    auto resolve_result =
        fptn::common::network::ResolveWithTimeout(ioc, sni, port_str, kTimeout);

    if (!resolve_result.success()) {
      SPDLOG_ERROR("Proxy DNS resolution failed for {}:{}: {}", sni, port_str,
          resolve_result.error.message());
      co_return false;
    }

    co_await boost::asio::async_connect(
        target_socket, resolve_result.results, boost::asio::use_awaitable);

    const auto ep = target_socket.remote_endpoint();
    SPDLOG_INFO("Proxying {}:{} <-> {}:{} (client_id={})",
        ep.address().to_string(), ep.port(), sni, port_str, client_id_);

    auto self = shared_from_this();
    auto forward = [self](
                       auto& from, auto& to) -> boost::asio::awaitable<void> {
      try {
        boost::system::error_code ec;
        std::array<std::uint8_t, 16384> buf{};
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

    // Set socket timeout
    SetSocketTimeouts(tcp_socket, kTimeout);
    SetSocketTimeouts(target_socket, kTimeout);

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

  // close socket
  try {
    tcp_socket.close();
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

boost::asio::awaitable<void> ClientEndpoint::RunReader() {
  boost::system::error_code ec;
  boost::beast::flat_buffer buffer;
  auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);
  try {
    while (running_ && ws_.is_open()) {
      co_await ws_.async_read(buffer, token);
      if (ec) {
        break;
      }
      if (buffer.size() > 0 && running_ && ws_.is_open()) {
        std::string raw_data = boost::beast::buffers_to_string(buffer.data());
        std::string raw_ip =
            fptn::protocol::protobuf::GetProtoPayload(std::move(raw_data));
        if (!raw_ip.empty() && running_ && ws_.is_open()) {
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

boost::asio::awaitable<void> ClientEndpoint::RunSender() {
  try {
    while (running_ && ws_.is_open()) {
      auto [ec, packet] = co_await write_channel_.async_receive(
          boost::asio::bind_cancellation_slot(cancel_signal_.slot(),
              boost::asio::as_tuple(boost::asio::use_awaitable)));
      if (running_ && ws_.is_open() && !ec && packet != nullptr) {
        std::string msg =
            fptn::protocol::protobuf::CreateProtoPayload(std::move(packet));
        if (!msg.empty()) {
          co_await ws_.async_write(
              boost::asio::buffer(msg), boost::asio::use_awaitable);
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

boost::asio::awaitable<bool> ClientEndpoint::ProcessRequest() {
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
    SPDLOG_ERROR("ClientEndpoint::handshake failed (client_id={}): {} [{}]",
        client_id_, err.what(), err.code().message());
  }
  co_return status;
}

boost::asio::awaitable<bool> ClientEndpoint::HandleHttp(
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
    SPDLOG_ERROR("ClientEndpoint::HandleHttp write error (client_id={}): {}",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR(
        "ClientEndpoint::HandleHttp write unknown error (client_id={})",
        client_id_);
  }
  co_return false;
}

boost::asio::awaitable<bool> ClientEndpoint::HandleWebSocket(
    const boost::beast::http::request<boost::beast::http::string_body>&
        request) {
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
  const std::string client_vpn_ipv6_str = request.contains("ClientIPv6")
                                              ? request["ClientIPv6"]
                                              : FPTN_CLIENT_DEFAULT_ADDRESS_IP6;

  if (request.contains("Authorization") && request.contains("ClientIP")) {
    try {
      fptn::nat::ConnectParams params = {};
      params.client_id = client_id_;

      params.request.url = request.target();
      params.request.session_id = ParseRequestStr(
          request, "SessionID", common::utils::GenerateRandomString(32));
      params.request.connection_weight =
          ParseRequestUint(request, "ConnectionWeight", 1);
      params.request.jwt_auth_token =
          common::utils::RemoveSubstring(request["Authorization"], {"Bearer "});

      params.request.client_ipv4 = client_ip_str;
      params.request.client_tun_vpn_ipv4 = request["ClientIP"];
      params.request.client_tun_vpn_ipv6 = client_vpn_ipv6_str;

      params.timings.SetExpireAfter(
          ParseRequestUint(request, "ExpireAfterTimestamp", 0));
      params.timings.SetExpireAfter(
          ParseRequestUint(request, "SilenceModeUntilTimestamp", 0));

      const bool status = ws_open_callback_(params, shared_from_this());
      ws_session_was_opened_ = status;

      co_return status;
    } catch (const std::exception& ex) {
      SPDLOG_ERROR(
          "ClientEndpoint::Open (client_id={}): Exception caught while "
          "creating IP "
          "addresses or running callback: {}",
          client_id_, ex.what());
    } catch (...) {
      SPDLOG_ERROR(
          "ClientEndpoint::Open (client_id={}): Unknown fatal error caught "
          "while "
          "creating IP addresses or running callback",
          client_id_);
    }
  }
  co_return false;
}

void ClientEndpoint::Close() {
  if (!running_) {
    return;
  }

  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  // cppcheck-suppress identicalConditionAfterEarlyExit
  if (!running_) {  // Double-check after acquiring lock
    return;
  }

  SPDLOG_INFO("Close session {}", client_id_);
  running_ = false;

  try {
    cancel_signal_.emit(boost::asio::cancellation_type::all);
    write_channel_.close();
  } catch (const std::exception& err) {
    SPDLOG_WARN(
        "Failed to cancel session or close write_channel: {}", err.what());
  } catch (...) {
    SPDLOG_WARN(
        "ClientEndpoint::Close unknown fatal error (client_id={})", client_id_);
  }
  // Close TCP socket first
  try {
    auto& tcp_layer = boost::beast::get_lowest_layer(ws_);
    if (tcp_layer.socket().is_open()) {
      boost::system::error_code ec;
      tcp_layer.expires_after(std::chrono::milliseconds(50));

      tcp_layer.socket().shutdown(
          boost::asio::ip::tcp::socket::shutdown_both, ec);
      tcp_layer.socket().close(ec);
    }
  } catch (const std::exception& err) {
    SPDLOG_WARN("ClientEndpoint::Close TCP socket error (client_id={}): {}",
        client_id_, err.what());
  } catch (...) {
    SPDLOG_WARN("ClientEndpoint::Close TCP socket unknown error (client_id={})",
        client_id_);
  }

  // Close WebSocket
  try {
    if (ws_.is_open()) {
      boost::system::error_code ec;
      ws_.close(boost::beast::websocket::close_code::normal, ec);
    }
  } catch (const std::exception& err) {
    SPDLOG_WARN("ClientEndpoint::Close WebSocket error (client_id={}): {}",
        client_id_, err.what());
  } catch (...) {
    SPDLOG_WARN("ClientEndpoint::Close WebSocket unknown error (client_id={})",
        client_id_);
  }

  // Close SSL
  try {
    auto& ssl_layer = ws_.next_layer();
    if (ssl_layer.native_handle()) {
      ::SSL_set_quiet_shutdown(ssl_layer.native_handle(), 1);
    }
  } catch (const std::exception& err) {
    SPDLOG_ERROR(
        "ClientEndpoint::Close SSL shutdown exception (client_id={}): {}",
        client_id_, err.what());
  } catch (...) {
    SPDLOG_ERROR(
        "ClientEndpoint::Close SSL shutdown unknown error (client_id={})",
        client_id_);
  }

  if (ws_close_callback_ && ws_session_was_opened_) {
    try {
      ws_close_callback_(client_id_);
    } catch (const std::exception& e) {
      SPDLOG_WARN("WebSocket close callback threw exception (client_id={}): {}",
          client_id_, e.what());
    } catch (...) {
      SPDLOG_WARN(
          "WebSocket close callback threw unknown exception (client_id={})",
          client_id_);
    }
  }
}

boost::asio::awaitable<bool> ClientEndpoint::Send(
    common::network::IPPacketPtr pkt) {
  auto self = shared_from_this();
  boost::asio::post(strand_, [self, pkt = std::move(pkt)]() mutable {
    if (self->running_ && self->write_channel_.is_open()) {
      const bool status = self->write_channel_.try_send(
          boost::system::error_code(), std::move(pkt));
      if (!status && !self->full_queue_) {
        self->full_queue_ = true;
        SPDLOG_WARN("ClientEndpoint::send queue is full (client_id={})",
            self->client_id_);
      }
    }
  });
  co_return true;
}

boost::asio::awaitable<IObfuscator> ClientEndpoint::DetectObfuscator() {
  try {
    auto& tcp_socket = boost::beast::get_lowest_layer(ws_).socket();

    // Peek data without consuming it from the socket buffer
    // This allows inspection without affecting subsequent reads
    std::array<std::uint8_t, 16384> buffer{};
    const std::size_t bytes_read =
        co_await tcp_socket.async_receive(boost::asio::buffer(buffer),
            boost::asio::socket_base::message_peek, boost::asio::use_awaitable);

    if (!bytes_read) {
      SPDLOG_WARN("No data received for obfuscator detection [client_id: {}]",
          client_id_);
      co_return std::nullopt;
    }

    // Detect the appropriate obfuscator based on the peeked data
    auto obfuscator = fptn::protocol::https::obfuscator::DetectObfuscator(
        buffer.data(), bytes_read);
    co_return obfuscator;
  } catch (const boost::system::system_error& e) {
    SPDLOG_ERROR(
        "System error during obfuscator setup [client_id: {}, error: '{}', "
        "code: {}]",
        client_id_, e.what(), e.code().message());
  } catch (const std::exception& e) {
    SPDLOG_ERROR(
        "Exception during obfuscator setup [client_id: {}, error: '{}']",
        client_id_, e.what());
  } catch (...) {
    SPDLOG_ERROR(
        "Unknown error during obfuscator setup [client_id: {}]", client_id_);
  }
  co_return std::nullopt;
}

};  // namespace fptn::web
