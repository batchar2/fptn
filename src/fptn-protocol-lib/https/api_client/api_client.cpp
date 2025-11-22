/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/api_client/api_client.h"

#include <chrono>
#include <memory>
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

};  // namespace

namespace fptn::protocol::https {

using tcp_stream_type = boost::beast::tcp_stream;
using obfuscator_socket_type = obfuscator::TcpStream<tcp_stream_type>;
using ssl_stream_type = boost::beast::ssl_stream<obfuscator_socket_type>;

ApiClient::ApiClient(
    const std::string& host, int port, obfuscator::IObfuscatorSPtr obfuscator)
    : host_(host),
      port_(port),
      sni_(host),
      obfuscator_(std::move(obfuscator)) {}  // NOLINT

ApiClient::ApiClient(std::string host,
    int port,
    std::string sni,
    obfuscator::IObfuscatorSPtr obfuscator)
    : host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      obfuscator_(std::move(obfuscator)) {}  // NOLINT

ApiClient::ApiClient(std::string host,
    int port,
    std::string sni,
    std::string md5_fingerprint,
    obfuscator::IObfuscatorSPtr obfuscator)
    : host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      expected_md5_fingerprint_(std::move(md5_fingerprint)),
      obfuscator_(std::move(obfuscator)) {}  // NOLINT

Response ApiClient::Get(const std::string& handle, int timeout) const {
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

    tcp_stream_type tcp_stream(ioc);
    obfuscator_socket_type obfuscator_stream(
        std::move(tcp_stream), obfuscator_);
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

      if (obfuscator_ != nullptr) {
        constexpr int kMaxRetries = 5;
        int retry_count = 0;
        do {
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
          retry_count += 1;
        } while (obfuscator_->HasPendingData() && retry_count < kMaxRetries);
        if (retry_count >= kMaxRetries) {
          SPDLOG_WARN(
              "GET [{}] - Failed to clear obfuscator pending data within {} "
              "attempts for server: {}",
              handle, retry_count, host_);
        }
        stream.next_layer().set_obfuscator(nullptr);
      }

      boost::beast::http::request<boost::beast::http::string_body> req{
          boost::beast::http::verb::get, handle, 11};
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

Response ApiClient::Post(const std::string& handle,
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

    tcp_stream_type tcp_stream(ioc);
    obfuscator_socket_type obfuscator_stream(
        std::move(tcp_stream), obfuscator_);
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

      if (obfuscator_ != nullptr) {
        constexpr int kMaxRetries = 5;
        int retry_count = 0;
        do {
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
          retry_count += 1;
        } while (obfuscator_->HasPendingData() && retry_count < kMaxRetries);
        if (retry_count >= kMaxRetries) {
          SPDLOG_WARN(
              "POST [{}] - Failed to clear obfuscator pending data within {} "
              "attempts for server: {}",
              handle, retry_count, host_);
        }
        stream.next_layer().set_obfuscator(nullptr);
      }

      boost::beast::http::request<boost::beast::http::string_body> req{
          boost::beast::http::verb::post, handle, 11};
      req.set(boost::beast::http::field::host, host_);
      req.set(boost::beast::http::field::content_type, content_type);
      req.set(boost::beast::http::field::content_length,
          std::to_string(request.size()));
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
