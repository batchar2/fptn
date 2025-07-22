/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/https_client.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

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
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/detail/openssl_types.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/nowide/convert.hpp>

#include "fptn-protocol-lib/tls/tls.h"

#ifdef _WIN32
#pragma warning(pop)
#endif

using fptn::protocol::https::HttpsClient;
using fptn::protocol::https::Response;

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
      return {};  // decompression error
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

};  // namespace

namespace fptn::protocol::https {

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
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
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
#error "Unsupported system!"
#endif
}
};  // namespace fptn::protocol::https

HttpsClient::HttpsClient(const std::string& host, int port)
    : host_(host), port_(port), sni_(host) {}

HttpsClient::HttpsClient(std::string host, int port, std::string sni)
    : host_(std::move(host)), port_(port), sni_(std::move(sni)) {}

HttpsClient::HttpsClient(
    std::string host, int port, std::string sni, std::string md5_fingerprint)
    : host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      expected_md5_fingerprint_(std::move(md5_fingerprint)) {}

Response HttpsClient::Get(const std::string& handle, int timeout) {
  std::string body;
  std::string error;
  int respcode = 400;

  SSL* ssl = nullptr;
  try {
    boost::asio::io_context ioc;

    SSL_CTX* ssl_ctx = fptn::protocol::tls::CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    boost::beast::net::ip::tcp::resolver resolver(ioc);
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream(ioc, ctx);

    const std::string port = std::to_string(port_);
    auto const results = resolver.resolve(host_, port);
    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));
    boost::beast::get_lowest_layer(stream).connect(results);

    fptn::protocol::tls::SetHandshakeSessionID(stream.native_handle());
    fptn::protocol::tls::SetHandshakeSni(stream.native_handle(), sni_);

    if (!expected_md5_fingerprint_.empty()) {
      ssl = stream.native_handle();
      fptn::protocol::tls::AttachCertificateVerificationCallback(
          ssl, [this, &error](const std::string& md5_fingerprint) {
            return onVerifyCertificate(md5_fingerprint, error);
          });
    } else {
      ctx.set_verify_mode(boost::asio::ssl::verify_none);
    }

    stream.handshake(boost::asio::ssl::stream_base::client);

    boost::beast::http::request<boost::beast::http::string_body> req{
        boost::beast::http::verb::get, handle, 11};
    const auto headers = RealBrowserHeaders(sni_);
    for (const auto& [key, value] : headers) {
      req.set(key, value);
    }

    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));
    boost::beast::http::write(stream, req);

    boost::beast::flat_buffer buffer;
    boost::beast::http::response<boost::beast::http::dynamic_body> res;
    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));
    boost::beast::http::read(stream, buffer, res);

    respcode = static_cast<int>(res.result_int());
    body = GetHttpBody(res);

    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));

    boost::system::error_code ec;
    stream.shutdown(ec);
    try {
      boost::beast::get_lowest_layer(stream).close();
    } catch (boost::system::system_error const& e) {
      SPDLOG_ERROR("Exception during HttpsClient::Get: {}", e.what());
    }
  } catch (const boost::system::system_error& err) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(err.what()));
#else
    error = err.what();
#endif
    respcode = 600;
    SPDLOG_ERROR("Exception during HttpsClient::Get: {}", error);
  } catch (const std::exception& e) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(e.what()));
#else
    error = e.what();
#endif
    respcode = 601;
    SPDLOG_ERROR("Exception during HttpsClient::Get: {}", error);
  } catch (...) {
    error = "Unknown exception";
    respcode = 602;
    SPDLOG_ERROR("Unknown exception occurred during HttpsClient::Get");
  }
  if (ssl) {
    fptn::protocol::tls::AttachCertificateVerificationCallbackDelete(ssl);
  }
  return {body, respcode, error};
}

Response HttpsClient::Post(const std::string& handle,
    const std::string& request,
    const std::string& content_type,
    int timeout) {
  std::string body;
  std::string error;
  int respcode = 400;

  SSL* ssl = nullptr;
  try {
    boost::asio::io_context ioc;
    SSL_CTX* ssl_ctx = fptn::protocol::tls::CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    boost::beast::net::ip::tcp::resolver resolver(ioc);
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream(ioc, ctx);

    const std::string port = std::to_string(port_);
    auto const results = resolver.resolve(host_, port);

    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));
    boost::beast::get_lowest_layer(stream).connect(results);

    fptn::protocol::tls::SetHandshakeSessionID(stream.native_handle());
    fptn::protocol::tls::SetHandshakeSni(stream.native_handle(), sni_);

    if (!expected_md5_fingerprint_.empty()) {
      ssl = stream.native_handle();
      fptn::protocol::tls::AttachCertificateVerificationCallback(
          ssl, [this, &error](const std::string& md5_fingerprint) {
            return onVerifyCertificate(md5_fingerprint, error);
          });
    } else {
      ctx.set_verify_mode(boost::asio::ssl::verify_none);
    }

    stream.handshake(boost::asio::ssl::stream_base::client);

    boost::beast::http::request<boost::beast::http::string_body> req{
        boost::beast::http::verb::post, handle, 11};
    req.set(boost::beast::http::field::host, host_);
    req.set(boost::beast::http::field::content_type, content_type);
    req.set(boost::beast::http::field::content_length,
        std::to_string(request.size()));
    const auto headers = RealBrowserHeaders(sni_);
    for (const auto& [key, value] : headers) {
      req.set(key, value);
    }
    req.body() = request;
    req.prepare_payload();

    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));
    boost::beast::http::write(stream, req);

    boost::beast::flat_buffer buffer;
    boost::beast::http::response<boost::beast::http::dynamic_body> res;
    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));
    boost::beast::http::read(stream, buffer, res);

    respcode = static_cast<int>(res.result_int());
    body = GetHttpBody(res);

    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));
    boost::system::error_code ec;
    stream.shutdown(ec);
    try {
      boost::beast::get_lowest_layer(stream).close();
    } catch (boost::system::system_error const& e) {
      SPDLOG_ERROR("Exception during HttpsClient::Get: {}", e.what());
    }
  } catch (const boost::system::system_error& err) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(err.what()));
#else
    error = err.what();
#endif
    respcode = 600;
    SPDLOG_ERROR("Exception during HttpsClient::Post: {}", error);
  } catch (const std::exception& e) {
#ifdef _WIN32
    error = boost::nowide::narrow(boost::nowide::widen(e.what()));
#else
    error = e.what();
#endif
    respcode = 601;
    SPDLOG_ERROR("Exception during HttpsClient::Post: {}", error);
  } catch (...) {
    error = "Unknown exception";
    respcode = 602;
    SPDLOG_ERROR("Unknown exception occurred during HttpsClient::Post");
  }
  if (ssl) {
    fptn::protocol::tls::AttachCertificateVerificationCallbackDelete(ssl);
  }
  return {body, respcode, error};
}

bool HttpsClient::onVerifyCertificate(
    const std::string& md5_fingerprint, std::string& error) const {
  if (md5_fingerprint == expected_md5_fingerprint_) {
    SPDLOG_INFO("Certificate verified successfully (MD5 matched: {}).",
        md5_fingerprint);
    return true;
  }
  error = fmt::format(
      "Certificate MD5 mismatch. Expected: {}, got: {}. "
      "Please update your token.",
      expected_md5_fingerprint_, md5_fingerprint);
  SPDLOG_ERROR(error);
  return false;
}
