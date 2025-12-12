/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/api_client/api_client.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fmt/format.h>     // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)
#include <zlib.h>           // NOLINT(build/include_order)

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4996)
#pragma warning(disable : 4267)
#pragma warning(disable : 4244)
#pragma warning(disable : 4702)
#endif

#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/detail/openssl_types.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/nowide/convert.hpp>

#include "common/network/resolv.h"

#include "fptn-protocol-lib/https/obfuscator/methods/tls/tls_obfuscator.h"
#include "fptn-protocol-lib/https/obfuscator/tcp_stream/tcp_stream.h"
#include "fptn-protocol-lib/https/utils/tls/tls.h"

#ifdef _WIN32
#pragma warning(pop)
#endif

namespace {

std::string DecompressGzip(const std::string& compressed) {
  constexpr std::size_t kChunkSize = 4096;

  std::vector<char> buffer(kChunkSize);

  ::z_stream strm{};
  strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
  strm.avail_in = static_cast<unsigned int>(compressed.size());

  if (::inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
    return {};
  }

  std::string decompressed;
  int ret = 0;
  do {
    strm.next_out = reinterpret_cast<Bytef*>(buffer.data());
    strm.avail_out = static_cast<unsigned int>(buffer.size());
    ret = inflate(&strm, Z_NO_FLUSH);

    if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
      inflateEnd(&strm);
      return {};
    }
    decompressed.append(buffer.data(), buffer.size() - strm.avail_out);
  } while (ret != Z_STREAM_END);

  inflateEnd(&strm);
  return decompressed;
}

std::string GetHttpBody(
    const boost::beast::http::response<boost::beast::http::dynamic_body>& res) {
  auto body = boost::beast::buffers_to_string(res.body().data());
  if (res[boost::beast::http::field::content_encoding] == "gzip") {
    return DecompressGzip(body);
  }
  return body;
}

void SetSocketTimeouts(
    boost::asio::ip::tcp::socket& socket, int timeout_seconds) {
  auto native_socket = socket.native_handle();

#ifdef _WIN32
  DWORD timeout_ms = timeout_seconds * 1000;
  ::setsockopt(native_socket, SOL_SOCKET, SO_RCVTIMEO,
      reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
  ::setsockopt(native_socket, SOL_SOCKET, SO_SNDTIMEO,
      reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
  timeval tv = {};
  tv.tv_sec = timeout_seconds;
  tv.tv_usec = 0;
  ::setsockopt(native_socket, SOL_SOCKET, SO_RCVTIMEO,
      reinterpret_cast<const char*>(&tv), sizeof(tv));
  ::setsockopt(native_socket, SOL_SOCKET, SO_SNDTIMEO,
      reinterpret_cast<const char*>(&tv), sizeof(tv));
#endif
}

using Headers = std::unordered_map<std::string, std::string>;

Headers RealBrowserHeaders(const std::string& host) {
  /* Just to ensure that FPTN is as similar to a web browser as possible. */
#ifdef __linux__  // chromium ubuntu arm
  return {{"Host", host},
      {"User-Agent",
          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
          "Gecko) Chrome/134.0.0.0 Safari/537.36"},
      {"Accept-Language", "en-US,en;q=0.9"},
      {"Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/"
          "avif,image/webp,image/apng,*/*;q=0.8,application/"
          "signed-exchange;v=b3;q=0.7"},
      {"Referer", "https://www.google.com/"},
      {"Accept-Encoding", "gzip, deflate, br, zstd"},
      {"Sec-Ch-Ua", R"("Not:A-Brand";v="24", "Chromium";v="134")"},
      {"Sec-Ch-Ua-Mobile", "?0"}, {"Sec-Ch-Ua-Platform", R"("Linux")"},
      {"Upgrade-Insecure-Requests", "1"}, {"Sec-Fetch-Site", "cross-site"},
      {"Sec-Fetch-Mode", "navigate"}, {"Sec-Fetch-User", "?1"},
      {"Sec-Fetch-Dest", "document"}, {"Priority", "u=0, i"}};
#elif __APPLE__
  // apple silicon chrome
  return {{"Host", host},
      {"sec-ch-ua",
          R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
      {"sec-ch-ua-platform", "\"macOS\""}, {"sec-ch-ua-mobile", "?0"},
      {"upgrade-insecure-requests", "1"},
      {"User-Agent",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
      {"Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/"
          "avif,image/webp,image/apng,*/*;q=0.8,application/"
          "signed-exchange;v=b3;q=0.7"},
      {"sec-fetch-site", "none"}, {"sec-fetch-mode", "no-cors"},
      {"sec-fetch-dest", "empty"}, {"Referer", "https://www.google.com/"},
      {"Accept-Encoding", "gzip, deflate, br"},
      {"Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
      {"priority", "u=4, i"}};
#elif _WIN32
  // chrome windows amd64
  return {{"Host", host},
      {"sec-ch-ua",
          R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
      {"sec-ch-ua-mobile", "?0"}, {"sec-ch-ua-platform", "\"Windows\""},
      {"upgrade-insecure-requests", "1"},
      {"User-Agent",
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
      {"Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/"
          "avif,image/webp,image/apng,*/*;q=0.8,application/"
          "signed-exchange;v=b3;q=0.7"},
      {"sec-fetch-site", "cross-site"}, {"sec-fetch-mode", "navigate"},
      {"sec-fetch-user", "?1"}, {"sec-fetch-dest", "document"},
      {"Referer", "https://www.google.com/"},
      {"Accept-Encoding", "gzip, deflate, br, zstd"},
      {"Accept-Language", "en-US,en;q=0.9,ru;q=0.8"}, {"priority", "u=0, i"}};
#else
#error Undefined platform
#endif
}

template <typename TResult>
TResult ExecuteWithTimeout(const std::function<TResult()>& operation,
    int timeout,
    const std::string& operation_name,
    const std::string& handle,
    const std::string& host,
    const TResult& timeout_result) {
  try {
    // Shared state
    struct SharedState {
      std::mutex mutex;
      std::condition_variable cv;
      bool ready = false;
      TResult result;
      std::atomic<bool> cancelled{false};
    };

    const auto start_time = std::chrono::steady_clock::now();

    auto state = std::make_shared<SharedState>();

    // NOLINTNEXTLINE(bugprone-exception-escape)
    std::weak_ptr<SharedState> weak_state = state;
    std::thread([weak_state, operation]() {
      TResult impl_result = operation();
      // check state
      if (auto state = weak_state.lock()) {
        const std::scoped_lock<std::mutex> lock(state->mutex);
        if (!state->cancelled) {
          state->result = impl_result;
          state->ready = true;
          state->cv.notify_one();
        }
      }
    }).detach();

    std::unique_lock<std::mutex> lock(state->mutex);
    if (!state->cv.wait_for(lock, std::chrono::seconds(timeout),
            [state]() { return state->ready; })) {
      const auto end_time = std::chrono::steady_clock::now();
      const auto duration =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              end_time - start_time);

      state->cancelled = true;

      SPDLOG_WARN("{} [{}] - Timeout after {} ms for server {}", operation_name,
          handle, duration.count(), host);
      return timeout_result;
    }
    return state->result;
  } catch (...) {
    SPDLOG_ERROR("Undefined error: {} {}", operation_name, handle);
  }
  return timeout_result;
}

};  // namespace

namespace fptn::protocol::https {

using tcp_stream_type = boost::beast::tcp_stream;
using obfuscator_socket_type = obfuscator::TcpStream<tcp_stream_type>;
using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;

ApiClient::ApiClient(
    const std::string& host, int port, CensorshipStrategy censorship_strategy)
    : host_(host),
      port_(port),
      sni_(host),
      censorship_strategy_(censorship_strategy) {}  // NOLINT

ApiClient::ApiClient(std::string host,
    int port,
    std::string sni,
    CensorshipStrategy censorship_strategy)
    : host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      censorship_strategy_(censorship_strategy) {}  // NOLINT

ApiClient::ApiClient(std::string host,
    int port,
    std::string sni,
    std::string md5_fingerprint,
    CensorshipStrategy censorship_strategy)
    : host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      expected_md5_fingerprint_(std::move(md5_fingerprint)),
      censorship_strategy_(censorship_strategy) {}  // NOLINT

Response ApiClient::Get(const std::string& handle, int timeout) const {
  // NOLINTNEXTLINE(bugprone-exception-escape)
  return ExecuteWithTimeout<Response>(
      // NOLINTNEXTLINE(bugprone-exception-escape)
      [this, handle, timeout]() {
        const ApiClient cloned_client = Clone();
        return cloned_client.GetImpl(handle, timeout);
      },
      timeout, "GET", handle, host_, Response{"", 608, "Operation timeout"});
}

Response ApiClient::Post(const std::string& handle,
    const std::string& request,
    const std::string& content_type,
    int timeout) const {
  // NOLINTNEXTLINE(bugprone-exception-escape)
  return ExecuteWithTimeout<Response>(
      // NOLINTNEXTLINE(bugprone-exception-escape)
      [this, handle, request, content_type, timeout]() {
        const ApiClient cloned_client = Clone();
        return cloned_client.PostImpl(handle, request, content_type, timeout);
      },
      timeout, "POST", handle, host_, Response{"", 608, "Operation timeout"});
}

bool ApiClient::TestHandshake(int timeout) const {
  // NOLINTNEXTLINE(bugprone-exception-escape)
  return ExecuteWithTimeout<bool>(
      // NOLINTNEXTLINE(bugprone-exception-escape)
      [this, timeout]() {
        const ApiClient cloned_client = Clone();
        return cloned_client.TestHandshakeImpl(timeout);
      },
      timeout, "TestHandshake", "", host_, false);
}

ApiClient ApiClient::Clone() const {
  ApiClient temp_client(
      host_, port_, sni_, expected_md5_fingerprint_, censorship_strategy_);
  return temp_client;
}

bool ApiClient::PerformFakeHandshake(
    boost::asio::ip::tcp::socket& socket) const {
  boost::system::error_code ec;
  try {
    SPDLOG_INFO("Generating and sending fake TLS handshake to {}", sni_);

    const auto handshake_data = utils::GenerateDecoyTlsHandshake(sni_);
    if (handshake_data.empty()) {
      SPDLOG_WARN("Failed to generate handshake data for SNI: {}", sni_);
      return false;
    }

    SPDLOG_INFO(
        "Sending {} bytes of handshake data over TCP", handshake_data.size());

    const std::size_t bytes_sent =
        boost::asio::write(socket, boost::asio::buffer(handshake_data));

    SPDLOG_INFO("Successfully sent {} bytes of handshake data", bytes_sent);

    std::vector<std::uint8_t> server_response(16384);
    do {
      const std::size_t bytes_read =
          socket.read_some(boost::asio::buffer(server_response), ec);
      if (bytes_read != 0) {
        SPDLOG_INFO("Received {}", bytes_read);
        break;
      }
      if (ec) {
        SPDLOG_INFO("Received error: {}", ec.what());
        break;
      }
    } while (true);

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    if (!ec) {
      SPDLOG_INFO("Received {} bytes server response (ignored)",
          server_response.size());
    }
    SPDLOG_INFO("Fake handshake completed successfully");
    return true;
  } catch (const std::exception& e) {
    SPDLOG_ERROR("PerformFakeHandshake exception: {}", e.what());
  }
  return false;
}

Response ApiClient::GetImpl(const std::string& handle, int timeout) const {
  std::string body;
  std::string error;
  int respcode = 400;

  const auto start_time = std::chrono::steady_clock::now();

  SSL* ssl = nullptr;
  std::string server_ip;
  try {
    boost::asio::io_context ioc;

    auto* ssl_ctx = fptn::protocol::https::utils::CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator = nullptr;
    if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
      obfuscator =
          std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator>();
    }

    tcp_stream_type tcp_stream(ioc);
    obfuscator_socket_type obfuscator_stream(std::move(tcp_stream), obfuscator);
    ssl_stream_type stream(std::move(obfuscator_stream), ctx);

    const std::string port_str = std::to_string(port_);
    auto resolve_result = fptn::common::network::ResolveWithTimeout(
        ioc, host_, port_str, timeout);

    if (!resolve_result) {
      error = resolve_result.error.message();
      respcode = 603;
      SPDLOG_ERROR("GET [{}] - DNS resolution failed for {}:{}: {}", handle,
          host_, port_, error);
    } else {
      SPDLOG_INFO(
          "GET [{}] - Connecting to server: {}:{}", handle, host_, port_);

      boost::beast::get_lowest_layer(stream).expires_after(
          std::chrono::seconds(timeout));
      stream.next_layer().next_layer().expires_after(
          std::chrono::seconds(timeout));

      auto connected_endpoint = boost::beast::get_lowest_layer(stream).connect(
          resolve_result.results);
      server_ip = connected_endpoint.address().to_string();

      SPDLOG_INFO("GET [{}] - Successfully connected to {}", handle, host_);

      auto& socket = boost::beast::get_lowest_layer(stream).socket();
      SetSocketTimeouts(socket, timeout);

      // Perform fake handshake if enabled
      if (censorship_strategy_ == CensorshipStrategy::kSniRealityMode) {
        const bool perform_status = PerformFakeHandshake(socket);
        if (!perform_status) {
          SPDLOG_WARN(
              "GET [{}] - Fake handshake failed, continuing with real "
              "handshake",
              handle);
        }
        // For Reality Mode we use TLS obfuscator after fake handshake
        // This provides additional encryption layer for the real connection
        stream.next_layer().set_obfuscator(
            std::make_shared<protocol::https::obfuscator::TlsObfuscator>());
      }

      utils::SetHandshakeSessionID(stream.native_handle());
      utils::SetHandshakeSni(stream.native_handle(), sni_);
      if (!expected_md5_fingerprint_.empty()) {
        ssl = stream.native_handle();
        utils::AttachCertificateVerificationCallback(
            ssl, [this, &error](const std::string& md5_fingerprint) {
              return onVerifyCertificate(md5_fingerprint, error);
            });
      } else {
        ctx.set_verify_mode(boost::asio::ssl::verify_none);
      }

      stream.handshake(boost::asio::ssl::stream_base::client);

      if (obfuscator != nullptr) {
        constexpr int kMaxRetries = 5;
        int retry_count = 0;
        do {
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
          retry_count += 1;
        } while (obfuscator->HasPendingData() && retry_count < kMaxRetries);
        if (retry_count >= kMaxRetries) {
          SPDLOG_WARN(
              "GET [{}] - Failed to clear obfuscator pending data within {} "
              "attempts for server: {}",
              handle, retry_count, host_);
        }
      }
      stream.next_layer().set_obfuscator(nullptr);

      boost::beast::http::request<boost::beast::http::string_body> req{
          boost::beast::http::verb::get, handle, 11};

      // set http headers
      const auto headers = RealBrowserHeaders(sni_);
      for (const auto& [key, value] : headers) {
        req.set(key, value);
      }

      boost::beast::http::write(stream, req);

      boost::beast::flat_buffer buffer;
      boost::beast::http::response<boost::beast::http::dynamic_body> res;

      boost::beast::http::read(stream, buffer, res);

      respcode = static_cast<int>(res.result_int());
      body = GetHttpBody(res);

      boost::system::error_code ec;
      stream.shutdown(ec);
      try {
        boost::beast::get_lowest_layer(stream).close();
      } catch (boost::system::system_error const& e) {
        SPDLOG_ERROR(
            "GET [{}] - Exception during connection close for server {}: {}",
            handle, host_, e.what());
      }
    }
  } catch (const boost::system::system_error& err) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(err.what()));
#else
    error = err.what();
#endif
    respcode = 600;
    SPDLOG_ERROR("GET [{}] - System error for server {} (IP: {}): {}", handle,
        host_, server_ip, error);
  } catch (const std::exception& e) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(e.what()));
#else
    error = e.what();
#endif
    respcode = 601;
    SPDLOG_ERROR("GET [{}] - Exception for server {} (IP: {}): {}", handle,
        host_, server_ip, error);
  } catch (...) {
    error = "Unknown exception";
    respcode = 602;
    SPDLOG_ERROR("GET [{}] - Unknown exception for server {} (IP: {})", handle,
        host_, server_ip);
  }
  if (ssl) {
    utils::AttachCertificateVerificationCallbackDelete(ssl);
  }

  const auto end_time = std::chrono::steady_clock::now();
  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  if (respcode >= 200 && respcode < 300) {
    SPDLOG_INFO(
        "GET [{}] - Success from server {} (IP: {}) in {} ms - Status: {}, "
        "Body size: {} bytes",
        handle, host_, server_ip, duration.count(), respcode, body.size());
  } else {
    SPDLOG_WARN(
        "GET [{}] - Failed from server {} (IP: {}) in {} ms - Status: {}, "
        "Error: {}, Body size: {} bytes",
        handle, host_, server_ip, duration.count(), respcode, error,
        body.size());
  }
  return {body, respcode, error};
}

Response ApiClient::PostImpl(const std::string& handle,
    const std::string& request,
    const std::string& content_type,
    int timeout) const {
  std::string body;
  std::string error;
  int respcode = 400;

  const auto start_time = std::chrono::steady_clock::now();

  SSL* ssl = nullptr;
  std::string server_ip;

  try {
    boost::asio::io_context ioc;
    auto* ssl_ctx = utils::CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator = nullptr;
    if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
      obfuscator =
          std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator>();
    }

    tcp_stream_type tcp_stream(ioc);
    obfuscator_socket_type obfuscator_stream(std::move(tcp_stream), obfuscator);
    ssl_stream_type stream(std::move(obfuscator_stream), ctx);

    const std::string port_str = std::to_string(port_);
    auto resolve_result = fptn::common::network::ResolveWithTimeout(
        ioc, host_, port_str, timeout);

    if (!resolve_result) {
      error = resolve_result.error.message();
      respcode = 603;
      SPDLOG_ERROR("POST [{}] - DNS resolution failed for {}:{}: {}", handle,
          host_, port_, error);
    } else {
      SPDLOG_INFO(
          "POST [{}] - Connecting to server: {}:{}", handle, host_, port_);

      boost::beast::get_lowest_layer(stream).expires_after(
          std::chrono::seconds(timeout));
      stream.next_layer().next_layer().expires_after(
          std::chrono::seconds(timeout));

      auto connected_endpoint = boost::beast::get_lowest_layer(stream).connect(
          resolve_result.results);
      server_ip = connected_endpoint.address().to_string();

      SPDLOG_INFO("POST [{}] - Successfully connected to {}", handle, host_);

      auto& socket = boost::beast::get_lowest_layer(stream).socket();
      SetSocketTimeouts(socket, timeout);

      // Perform fake handshake if enabled
      if (censorship_strategy_ == CensorshipStrategy::kSniRealityMode) {
        const bool perform_status = PerformFakeHandshake(socket);
        if (!perform_status) {
          SPDLOG_WARN(
              "GET [{}] - Fake handshake failed, continuing with real "
              "handshake",
              handle);
        }
        // For Reality Mode we use TLS obfuscator after fake handshake
        // This provides additional encryption layer for the real connection
        stream.next_layer().set_obfuscator(
            std::make_shared<protocol::https::obfuscator::TlsObfuscator>());
      }

      utils::SetHandshakeSessionID(stream.native_handle());
      utils::SetHandshakeSni(stream.native_handle(), sni_);
      if (!expected_md5_fingerprint_.empty()) {
        ssl = stream.native_handle();
        utils::AttachCertificateVerificationCallback(
            ssl, [this, &error](const std::string& md5_fingerprint) {
              return onVerifyCertificate(md5_fingerprint, error);
            });
      } else {
        ctx.set_verify_mode(boost::asio::ssl::verify_none);
      }

      stream.handshake(boost::asio::ssl::stream_base::client);

      if (obfuscator != nullptr) {
        constexpr int kMaxRetries = 5;
        int retry_count = 0;
        do {
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
          retry_count += 1;
        } while (obfuscator->HasPendingData() && retry_count < kMaxRetries);
        if (retry_count >= kMaxRetries) {
          SPDLOG_WARN(
              "POST [{}] - Failed to clear obfuscator pending data within {} "
              "attempts for server: {}",
              handle, retry_count, host_);
        }
      }
      stream.next_layer().set_obfuscator(nullptr);

      boost::beast::http::request<boost::beast::http::string_body> req{
          boost::beast::http::verb::post, handle, 11};
      req.set(boost::beast::http::field::host, host_);
      req.set(boost::beast::http::field::accept, "*/*");
      req.set(boost::beast::http::field::content_type, content_type);
      req.set(boost::beast::http::field::content_length,
          std::to_string(request.size()));

      // set http headers
      const auto headers = RealBrowserHeaders(sni_);
      for (const auto& [key, value] : headers) {
        req.set(key, value);
      }

      req.body() = request;
      req.prepare_payload();

      boost::beast::http::write(stream, req);

      boost::beast::flat_buffer buffer;
      boost::beast::http::response<boost::beast::http::dynamic_body> res;
      boost::beast::http::read(stream, buffer, res);

      respcode = static_cast<int>(res.result_int());
      body = GetHttpBody(res);

      boost::system::error_code ec;
      stream.shutdown(ec);
      try {
        boost::beast::get_lowest_layer(stream).close();
      } catch (boost::system::system_error const& e) {
        SPDLOG_ERROR(
            "POST [{}] - Exception during connection close for server {}: {}",
            handle, host_, e.what());
      }
    }
  } catch (const boost::system::system_error& err) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(err.what()));
#else
    error = err.what();
#endif
    respcode = 600;
    SPDLOG_ERROR("POST [{}] - System error for server {} (IP: {}): {}", handle,
        host_, server_ip, error);
  } catch (const std::exception& e) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(e.what()));
#else
    error = e.what();
#endif
    respcode = 601;
    SPDLOG_ERROR("POST [{}] - Exception for server {} (IP: {}): {}", handle,
        host_, server_ip, error);
  } catch (...) {
    error = "Unknown exception";
    respcode = 602;
    SPDLOG_ERROR("POST [{}] - Unknown exception for server {} (IP: {})", handle,
        host_, server_ip);
  }
  if (ssl) {
    utils::AttachCertificateVerificationCallbackDelete(ssl);
  }

  const auto end_time = std::chrono::steady_clock::now();
  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  if (respcode >= 200 && respcode < 300) {
    SPDLOG_INFO(
        "POST [{}] - Success from server {} (IP: {}) in {} ms - Status: {}, "
        "Request: {} bytes, Response: {} bytes",
        handle, host_, server_ip, duration.count(), respcode, request.size(),
        body.size());
  } else {
    SPDLOG_WARN(
        "POST [{}] - Failed from server {} (IP: {}) in {} ms - Status: {}, "
        "Error: {}, Request: {} bytes, Response: {} bytes",
        handle, host_, server_ip, duration.count(), respcode, error,
        request.size(), body.size());
  }
  return {body, respcode, error};
}

bool ApiClient::TestHandshakeImpl(int timeout) const {
  const auto start_time = std::chrono::steady_clock::now();
  std::string server_ip;
  SSL* ssl = nullptr;

  try {
    boost::asio::io_context ioc;
    auto* ssl_ctx = utils::CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    fptn::protocol::https::obfuscator::IObfuscatorSPtr obfuscator = nullptr;
    if (censorship_strategy_ == CensorshipStrategy::kTlsObfuscator) {
      obfuscator =
          std::make_shared<fptn::protocol::https::obfuscator::TlsObfuscator>();
    }

    tcp_stream_type tcp_stream(ioc);
    obfuscator_socket_type obfuscator_stream(std::move(tcp_stream), obfuscator);
    ssl_stream_type stream(std::move(obfuscator_stream), ctx);

    const std::string port_str = std::to_string(port_);
    auto resolve_result = fptn::common::network::ResolveWithTimeout(
        ioc, host_, port_str, timeout);

    if (!resolve_result) {
      SPDLOG_WARN("TestHandshake - DNS resolution failed for {}:{}: {}", host_,
          port_, resolve_result.error.message());

      const auto end_time = std::chrono::steady_clock::now();
      const auto duration =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              end_time - start_time);

      SPDLOG_WARN(
          "Handshake failed for server {} in {} ms - DNS resolution error",
          host_, duration.count());
      return false;
    }

    SPDLOG_INFO("TestHandshake - Connecting to server: {}:{}", host_, port_);

    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));
    stream.next_layer().next_layer().expires_after(
        std::chrono::seconds(timeout));

    auto connected_endpoint =
        boost::beast::get_lowest_layer(stream).connect(resolve_result.results);
    server_ip = connected_endpoint.address().to_string();

    SPDLOG_INFO("TestHandshake - Successfully connected to {} (IP: {})", host_,
        server_ip);

    auto& socket = boost::beast::get_lowest_layer(stream).socket();
    SetSocketTimeouts(socket, timeout);

    // Perform fake handshake if enabled
    if (censorship_strategy_ == CensorshipStrategy::kSniRealityMode) {
      SPDLOG_INFO("TestHandshake - Performing fake handshake");
      if (!PerformFakeHandshake(socket)) {
        SPDLOG_WARN(
            "TestHandshake - Fake handshake failed, continuing with real "
            "handshake");
      }
    }

    utils::SetHandshakeSessionID(stream.native_handle());
    utils::SetHandshakeSni(stream.native_handle(), sni_);

    if (!expected_md5_fingerprint_.empty()) {
      ssl = stream.native_handle();
      std::string error;
      utils::AttachCertificateVerificationCallback(
          ssl, [this, &error](const std::string& md5_fingerprint) {
            return onVerifyCertificate(md5_fingerprint, error);
          });
    } else {
      ctx.set_verify_mode(boost::asio::ssl::verify_none);
    }

    // Perform TLS handshake
    stream.handshake(boost::asio::ssl::stream_base::client);

    // Clean shutdown
    boost::system::error_code ec;
    stream.shutdown(ec);

    // Close connection
    boost::beast::get_lowest_layer(stream).close();

    const auto end_time = std::chrono::steady_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    SPDLOG_INFO("Handshake successful for server {} (IP: {}) in {} ms", host_,
        server_ip, duration.count());

    if (ssl) {
      utils::AttachCertificateVerificationCallbackDelete(ssl);
    }
    return true;
  } catch (const boost::system::system_error& err) {
    std::string host_copy = host_;
    std::string server_ip_copy = server_ip;
    std::string error_msg;

#ifdef _WIN32
    error_msg = boost::nowide::narrow(boost::nowide::widen(err.what()));
#else
    error_msg = err.what();
#endif

    SPDLOG_WARN("Handshake failed for server {} (IP: {}): {}", host_copy,
        server_ip_copy, error_msg);
  } catch (const std::exception& e) {
    // Создаем копии строк перед использованием в логгере
    std::string host_copy = host_;
    std::string server_ip_copy = server_ip;
    std::string error_msg;

#ifdef _WIN32
    error_msg = boost::nowide::narrow(boost::nowide::widen(e.what()));
#else
    error_msg = e.what();
#endif

    SPDLOG_WARN("Handshake failed for server {} (IP: {}): {}", host_copy,
        server_ip_copy, error_msg);
  } catch (...) {
    // Создаем копии строк перед использованием в логгере
    std::string host_copy = host_;
    std::string server_ip_copy = server_ip;

    SPDLOG_WARN("Handshake failed for server {} (IP: {}): Unknown exception",
        host_copy, server_ip_copy);
  }

  if (ssl) {
    utils::AttachCertificateVerificationCallbackDelete(ssl);
  }

  const auto end_time = std::chrono::steady_clock::now();
  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);

  SPDLOG_WARN("Handshake failed for server {} (IP: {}) in {} ms", host_,
      server_ip, duration.count());

  return false;
}

bool ApiClient::onVerifyCertificate(
    const std::string& md5_fingerprint, std::string& error) const {
  if (expected_md5_fingerprint_.empty()) {
    return true;
  }
  if (md5_fingerprint == expected_md5_fingerprint_) {
    return true;
  }
  error = fmt::format(
      "Certificate MD5 mismatch. Expected: {}, got: {}. "
      "Please update your token.",
      expected_md5_fingerprint_, md5_fingerprint);
  SPDLOG_ERROR(
      "Certificate verification failed for server {}: {}", host_, error);
  return false;
}

}  // namespace fptn::protocol::https
