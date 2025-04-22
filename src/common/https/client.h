/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <iostream>  // DELETE IT
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
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

namespace fptn::common::https {

inline std::string ChromeCiphers() noexcept {
// TLS_GREASE_6A6A:
// TLS_GREASE_IS_THE_WORD_5A
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

using Headers = std::unordered_map<std::string, std::string>;
inline Headers RealBrowserHeaders(const std::string& host, int port) noexcept {
  /* Just to ensure that FPTN is as similar to a web browser as possible. */
  const std::string hostHeader =
      (port == 443 ? host : fmt::format("{}:{}", host, port));
#ifdef __linux__  // chromium ubuntu arm
  return {{"Host", hostHeader},
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
  return {{"Host", hostHeader},
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
  return {{"Host", hostHeader},
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

inline SSL_CTX* CreateNewSslCtx() {
  SSL_CTX* handle = ::SSL_CTX_new(::TLS_method());
  // Set TLS version range (TLS 1.2-1.3)
  if (0 == SSL_CTX_set_min_proto_version(handle, TLS1_2_VERSION)) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set min version)"));
  }
  if (0 == SSL_CTX_set_max_proto_version(handle, TLS1_3_VERSION)) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set max version)"));
  }
  // Disable older versions (redundant with min/max versions)
  SSL_CTX_set_options(handle, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                  SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
  // Set ciphers
  const std::string ciphers_list = ChromeCiphers();
  if (0 == ::SSL_CTX_set_cipher_list(handle, ciphers_list.c_str())) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set ciphers)"));
  }
  // Set groups (Chrome's preferred order) // "0x0a0a:X25519:P-256:P-384:P-521:0x1a1a"
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
      "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:RSA+"
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
  SSL_CTX_set_session_cache_mode(handle, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
  SSL_CTX_set_grease_enabled(handle, 1);
  SSL_CTX_enable_ocsp_stapling(handle);

  // Set signed_certificate_timestamp
  SSL_CTX_set_signed_cert_timestamp_list(handle, nullptr, 0);

//  SSL_CTX_enable_ct();
//  SSL_CTX_set_ct_validation_callback(
//      handle,
//      SSL_CTX_get_default_ct_validation_callback()
//  );
//  SSL_CTX_set_signed_certificate_timestamp(handle, 1);

//  SSL_CTX_set_signed_cert_timestamp_list

  return handle;
}

inline bool SetupSni(SSL* ssl, const std::string& sni) {
  // Set SNI (Server Name)
  if (ssl && 1 != ::SSL_set_tlsext_host_name(ssl, sni.c_str())) {
    throw boost::beast::system_error(
        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
            boost::asio::error::get_ssl_category()),
        fmt::format(R"(Failed to set SNI "{}")", sni));
  }
  if (ssl) {
    // Add Chrome-like padding (to match packet size)
    SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
  }
  return true;
}

inline bool SetupSSL(SSL_CTX* ctx, SSL* ssl, const std::string& sni) {
  (void)ctx;
  (void)ssl;
  (void)sni;
  return true;
}
//  if (ssl != nullptr) {
//    ::SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_ENABLE_FALSE_START);
//  }
//  // Force TLS 1.2-1.3 only
//  SSL_CTX_set_options(
//      ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
////  if (0 == SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
////    throw boost::beast::system_error(
////        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
////            boost::asio::error::get_ssl_category()),
////        fmt::format(R"(Failed to set min version)"));
////  }
//
//  if (0 == SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
//    throw boost::beast::system_error(
//        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
//            boost::asio::error::get_ssl_category()),
//        fmt::format(R"(Failed to set min version)"));
//  }
//  if (0 == SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) {
//    throw boost::beast::system_error(
//        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
//            boost::asio::error::get_ssl_category()),
//        fmt::format(R"(Failed to set max version)"));
//  }
//
//  //  ::SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
//  //  ::SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
//  //  ::SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
//  // Disable SSLv2
//  //  ::SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
//  //  // Disable SSLv3
//  //  ::SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
//  //  // Disable TLSv1
//  //  ::SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
//  //  // Disable TLSv1.1
//  //  ::SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
//
//  // Set ALPN (Application-Layer Protocol Negotiation)
//  static unsigned char alpn[] = {
//      0x02, 'h', '2',                               // h2
//      0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'  // http/1.1
//  };
//  //  static const unsigned char alpn[] = {4, 'e', 'c', 'h', 'o'};
//  if (0 != ::SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn))) {
//    throw boost::beast::system_error(
//        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
//            boost::asio::error::get_ssl_category()),
//        fmt::format(R"(Failed to set ALPN)"));
//  }
////  SSL_CTX_set_alpn_select_cb(
////      ctx,
////      [](SSL* ssl, const uint8_t** out, uint8_t* outlen, const uint8_t* in,
/// unsigned inlen, void* arg) -> int { /        (void)arg; /        static
/// unsigned char alpn[] = { /            0x02, 'h', '2', // h2 / 0x08, 'h',
/// 't', 't', 'p', '/', '1', '.', '1'  // http/1.1 /        }; /        const
/// uint8_t* alpn_data = &alpn[0]; /        std::size_t alpn_data_size =
/// sizeof(alpn);
////
////        if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
/// alpn_data, alpn_data_size, in, inlen) != OPENSSL_NPN_NEGOTIATED) { /
/// std::cerr << "+++1" << std::endl; /          return SSL_TLSEXT_ERR_NOACK; /
///} else { /          std::cerr << "---1" << std::endl; /          return
/// SSL_TLSEXT_ERR_OK; /        }
//////        auto state = reinterpret_cast<std::pair<uint16_t, bool>*>(arg);
//////        if (SSL_get_pending_cipher(ssl) != nullptr &&
//////            SSL_version(ssl) == state->first) {
//////          state->second = true;
//////        }
////        return SSL_TLSEXT_ERR_NOACK;
////      },
////      nullptr);
//
//  const std::string ciphers_list = ChromeCiphers();
//  if (0 == ::SSL_CTX_set_cipher_list(ctx, ciphers_list.c_str())) {
//    throw boost::beast::system_error(
//        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
//            boost::asio::error::get_ssl_category()),
//        fmt::format(R"(Failed to set ciphers)"));
//  }
//
//  // !!!!
//  if (1 != SSL_CTX_set1_groups_list(ctx, "P-256:X25519:P-384:P-521")) {
//    throw boost::beast::system_error(
//        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
//            boost::asio::error::get_ssl_category()),
//        fmt::format(R"(Failed to groups list)"));
//  }
//
//  // !!!! Chrome's preferred curves
//  SSL_CTX_set1_curves_list(ctx, "X25519:P-256:P-384:P-521");
//
//  // !!!!
//  const std::string sigalgs_list =
//      "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:RSA+"
//      "SHA384:RSA-PSS+SHA512:RSA+SHA512";
//  if (1 != SSL_CTX_set1_sigalgs_list(ctx, sigalgs_list.c_str())) {
//    throw boost::beast::system_error(
//        boost::beast::error_code(static_cast<int>(::ERR_get_error()),
//            boost::asio::error::get_ssl_category()),
//        fmt::format(R"(Failed to sigalgs list)"));
//  }
//
//  // Set SNI (Server Name)
//  if (ssl != nullptr) {
//    if (1 != ::SSL_set_tlsext_host_name(ssl, sni.c_str())) {
//      throw boost::beast::system_error(
//          boost::beast::error_code(static_cast<int>(::ERR_get_error()),
//              boost::asio::error::get_ssl_category()),
//          fmt::format(R"(Failed to set SNI "{}")", sni));
//    }
//  }
//  return true;
//}

struct Response final {
  const std::string body;
  const int code;
  const std::string errmsg;

  Response(std::string b, int c, std::string e)
      : body(std::move(b)), code(c), errmsg(std::move(e)) {}

  nlohmann::json Json() const { return nlohmann::json::parse(body); }
};

class Client final {
 public:
  // doesn't use sni
  explicit Client(const std::string& host, int port)
      : host_(host), port_(port), sni_(host) {}

  explicit Client(std::string host, int port, std::string sni)
      : host_(std::move(host)), port_(port), sni_(std::move(sni)) {}

  Response Get(const std::string& handle, int timeout = 5) noexcept {
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
      // SetupSSL(ctx.native_handle(), stream.native_handle(), sni_);

      SetupSni(stream.native_handle(), sni_);

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

  Response Post(const std::string& handle,
      const std::string& request,
      const std::string& content_type,
      int timeout = 5) noexcept {
    std::string body;
    std::string error;
    int respcode = 400;
    try {
      boost::asio::io_context ioc;
      //      boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
      //      boost::asio::ssl::context
      //      ctx(boost::asio::ssl::context::tlsv13_client);
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
//      SetupSSL(ctx.native_handle(), stream.native_handle(), sni_);
      SetupSni(stream.native_handle(), sni_);

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

 protected:
  std::string DecompressGzip(const std::string& compressed) {
    constexpr size_t CHUNK_SIZE = 4096;

    std::vector<char> buffer(CHUNK_SIZE);

    z_stream strm{};
    strm.next_in =
        reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
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
      const boost::beast::http::response<boost::beast::http::dynamic_body>&
          res) {
    const auto body = boost::beast::buffers_to_string(res.body().data());
    if (res[boost::beast::http::field::content_encoding] == "gzip") {
      return DecompressGzip(body);
    }
    return body;
  }

 private:
  const std::string host_;
  const int port_;
  const std::string sni_;
};

using ClientPtr = std::unique_ptr<Client>;
}  // namespace fptn::common::https
