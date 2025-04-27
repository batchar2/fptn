/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/https/https_client.h"

#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
#include <openssl/evp.h>    // NOLINT(build/include_order)
#include <openssl/rand.h>   // NOLINT(build/include_order)
#include <openssl/sha.h>    // NOLINT(build/include_order)
#include <openssl/ssl.h>    // NOLINT(build/include_order)
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
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>

#ifdef _WIN32
#pragma warning(pop)
#endif

using fptn::protocol::https::Headers;
using fptn::protocol::https::HttpsClient;
using fptn::protocol::https::Response;

namespace {

std::string DecompressGzip(const std::string& compressed) {
  constexpr std::size_t kChunkSize = 4096;

  std::vector<char> buffer(kChunkSize);

  ::z_stream strm{};
  strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
  strm.avail_in = static_cast<unsigned int>(compressed.size());

  if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
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

Headers HttpsClient::RealBrowserHeaders(const std::string& host, int port) {
  /* Just to ensure that FPTN is as similar to a web browser as possible. */
  const std::string host_header =
      (port == 443 ? host : fmt::format("{}:{}", host, port));
#ifdef __linux__  // chromium ubuntu arm
  return {{"Host", host_header},
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
  return {{"Host", host_header},
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
  return {{"Host", host_header},
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

std::string HttpsClient::GetSHA1Hash(std::uint32_t number) {
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    return {};
  }

  const EVP_MD* md = EVP_get_digestbyname("SHA1");
  if (!md) {
    EVP_MD_CTX_free(mdctx);
    return {};
  }

  if (!EVP_DigestInit_ex(mdctx, md, nullptr)) {
    EVP_MD_CTX_free(mdctx);
    return {};
  }

  if (!EVP_DigestUpdate(mdctx, &number, sizeof(number))) {
    EVP_MD_CTX_free(mdctx);
    return {};
  }

  unsigned int outlen = 0;
  unsigned char buffer[EVP_MAX_MD_SIZE] = {0};
  if (!EVP_DigestFinal_ex(mdctx, buffer, &outlen)) {
    EVP_MD_CTX_free(mdctx);
    return {};
  }
  EVP_MD_CTX_free(mdctx);
  return std::string(reinterpret_cast<const char*>(buffer), outlen);
}

std::string HttpsClient::GenerateFptnKey(std::uint32_t timestamp) {
  std::string result = GetSHA1Hash(htonl(timestamp));
  if (result.size() > 4) {  //  key len
    return result.substr(0, 4);
  }
  throw boost::beast::system_error(
      boost::beast::error_code(static_cast<int>(::ERR_get_error()),
          boost::asio::error::get_ssl_category()),
      "Error generate Session ID");
}

bool HttpsClient::SetHandshakeSessionID(SSL* ssl) {
  // random
  constexpr int kSessionLen = 32;
  std::uint8_t session_id[kSessionLen] = {0};
  if (::RAND_bytes(session_id, sizeof(session_id)) != 1) {
    return false;
  }
  // copy timestamp
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch());
  const auto timestamp = static_cast<std::uint32_t>(seconds.count());
  const std::string key = GenerateFptnKey(timestamp);

  std::memcpy(&session_id[kSessionLen - key.size()], key.c_str(), key.size());

  return 0 != ::SSL_set_tls_hello_custom_session_id(
                  ssl, session_id, sizeof(session_id));
}

bool HttpsClient::IsFptnClientSessionID(
    const std::uint8_t* session, std::size_t session_len) {
  char data[4] = {0};
  std::memcpy(&data, &session[session_len - sizeof(data)], sizeof(data));

  const std::string recv_key(data, sizeof(data));

  const auto now = std::chrono::system_clock::now();
  const auto now_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
          .count();
  const auto now_timestamp = static_cast<std::uint32_t>(now_seconds);

  constexpr std::uint32_t kTimeShiftSeconds = 3;
  for (std::uint32_t shift = 0; shift <= kTimeShiftSeconds; shift++) {
    const std::string key = GenerateFptnKey(now_timestamp - shift);
    if (recv_key == key) {
      return true;
    }
  }
  return false;
}

bool HttpsClient::SetHandshakeSni(SSL* ssl, const std::string& sni) {
  // Set SNI (Server Name)
  if (1 != ::SSL_set_tlsext_host_name(ssl, sni.c_str())) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set SNI "{}")", sni));
  }

  // Add Chrome-like padding (to match packet size)
  SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);

  SSL_set_enable_ech_grease(ssl, 1);
  return true;
}

SSL_CTX* HttpsClient::CreateNewSslCtx() {
  SSL_CTX* handle = ::SSL_CTX_new(::TLS_client_method());
  // Set TLS version range (TLS 1.2-1.3)
  if (0 == ::SSL_CTX_set_min_proto_version(handle, TLS1_2_VERSION)) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set min version)"));
  }
  if (0 == ::SSL_CTX_set_max_proto_version(handle, TLS1_3_VERSION)) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set max version)"));
  }
  // Disable older versions (redundant with min/max versions)
  ::SSL_CTX_set_options(handle, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
  // Set ciphers
  const std::string ciphers_list = ChromeCiphers();
  if (0 == ::SSL_CTX_set_cipher_list(handle, ciphers_list.c_str())) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set ciphers)"));
  }
  // Set groups (Chrome's preferred order)
  if (1 != SSL_CTX_set1_groups_list(handle, "P-256:X25519:P-384:P-521")) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to groups list)"));
  }

  // set alpn
  static unsigned char alpn[] = {
      0x02, 'h', '2',                               // h2
      0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'  // http/1.1
  };
  if (0 != ::SSL_CTX_set_alpn_protos(handle, alpn, sizeof(alpn))) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set ALPN)"));
  }

  // Set signature algorithms (Chrome's preferences)
  const std::string sigalgs_list =
      "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:"
      "RSA+"
      "SHA384:RSA-PSS+SHA512:RSA+SHA512";
  if (1 != SSL_CTX_set1_sigalgs_list(handle, sigalgs_list.c_str())) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to sigalgs list)"));
  }

  // Additional Chrome-like settings
  SSL_CTX_set_mode(handle, SSL_MODE_RELEASE_BUFFERS);
  // https://github.com/thatsacrylic/chromium/blob/7cfb85cef096c94f4d4255a712b05a53f87333f9/net/socket/ssl_client_socket_impl.cc#L308
  SSL_CTX_set_session_cache_mode(
      handle, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_set_grease_enabled(handle, 1);
  SSL_CTX_enable_ocsp_stapling(handle);

  SSL_CTX_set_session_cache_mode(handle, SSL_SESS_CACHE_OFF);

  return handle;
}

std::string HttpsClient::ChromeCiphers() {
  return "TLS_AES_128_GCM_SHA256:"
         "TLS_AES_256_GCM_SHA384:"
         "TLS_CHACHA20_POLY1305_SHA256:"
         "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
         "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
         "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
         "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
         "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
         "TLS_RSA_WITH_AES_128_GCM_SHA256:"
         "TLS_RSA_WITH_AES_256_GCM_SHA384:"
         "TLS_RSA_WITH_AES_128_CBC_SHA:"
         "TLS_RSA_WITH_AES_256_CBC_SHA";
}

HttpsClient::HttpsClient(const std::string& host, int port)
    : host_(host), port_(port), sni_(host) {}

HttpsClient::HttpsClient(std::string host, int port, std::string sni)
    : host_(std::move(host)), port_(port), sni_(std::move(sni)) {}

Response HttpsClient::Get(const std::string& handle, int timeout) {
  std::string body;
  std::string error;
  int respcode = 400;
  try {
    boost::asio::io_context ioc;

    SSL_CTX* ssl_ctx = CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    ctx.set_verify_mode(boost::asio::ssl::verify_none);  // disable validate

    boost::beast::net::ip::tcp::resolver resolver(ioc);
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream(ioc, ctx);

    const std::string port = std::to_string(port_);
    auto const results = resolver.resolve(host_, port);
    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));  // Set timeout for the operation
    boost::beast::get_lowest_layer(stream).connect(results);

    // Configure HTTPS protocol
    SetHandshakeSessionID(stream.native_handle());
    SetHandshakeSni(stream.native_handle(), sni_);

    stream.handshake(boost::asio::ssl::stream_base::client);

    // request params
    boost::beast::http::request<boost::beast::http::string_body> req{
        boost::beast::http::verb::get, handle, 11};
    // set http headers
    for (const auto& [key, value] : RealBrowserHeaders(sni_, port_)) {
      req.set(key, value);
    }
    // send request
    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));  // write timeout
    boost::beast::http::write(stream, req);
    // read answer
    boost::beast::flat_buffer buffer;
    boost::beast::http::response<boost::beast::http::dynamic_body> res;
    boost::beast::http::read(stream, buffer, res);

    respcode = static_cast<int>(res.result_int());
    body = GetHttpBody(res);

    boost::beast::error_code ec;
    stream.shutdown(ec);
    if (ec == boost::beast::net::error::eof) {
      ec = {};
    }
    if (ec) {
      throw boost::beast::system_error{ec};
    }
  } catch (std::exception const& e) {
    error = e.what();
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
  try {
    boost::asio::io_context ioc;
    SSL_CTX* ssl_ctx = CreateNewSslCtx();
    boost::asio::ssl::context ctx(ssl_ctx);

    ctx.set_verify_mode(boost::asio::ssl::verify_none);

    boost::beast::net::ip::tcp::resolver resolver(ioc);
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream(ioc, ctx);

    const std::string port = std::to_string(port_);
    auto const results = resolver.resolve(host_, port);
    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));  // Set timeout for the operation
    boost::beast::get_lowest_layer(stream).connect(results);

    // Configure HTTPS protocol
    SetHandshakeSessionID(stream.native_handle());
    SetHandshakeSni(stream.native_handle(), sni_);

    stream.handshake(boost::asio::ssl::stream_base::client);

    boost::beast::http::request<boost::beast::http::string_body> req{
        boost::beast::http::verb::post, handle, 11};
    req.set(boost::beast::http::field::host, host_);
    req.set(boost::beast::http::field::content_type, content_type);
    req.set(boost::beast::http::field::content_length,
        std::to_string(request.size()));
    for (const auto& [key, value] : RealBrowserHeaders(sni_, port_)) {
      req.set(key, value);
    }
    req.body() = request;
    req.prepare_payload();

    // send request
    boost::beast::get_lowest_layer(stream).expires_after(
        std::chrono::seconds(timeout));  // write timeout
    boost::beast::http::write(stream, req);

    boost::beast::flat_buffer buffer;
    boost::beast::http::response<boost::beast::http::dynamic_body> res;
    boost::beast::http::read(stream, buffer, res);

    respcode = static_cast<int>(res.result_int());
    body = GetHttpBody(res);

    boost::beast::error_code ec;
    stream.shutdown(ec);
    if (ec == boost::beast::net::error::eof) {
      ec = {};
    }
    if (ec) {
      throw boost::beast::system_error{ec};
    }
  } catch (std::exception const& e) {
    error = e.what();
  }
  return {body, respcode, error};
}
