/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tls/tls.h"

#include <string>

#include <boost/asio/ssl/detail/openssl_types.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/http.hpp>
#include <fmt/format.h>  // NOLINT(build/include_order)
#include <nlohmann/json.hpp>
#include <openssl/evp.h>   // NOLINT(build/include_order)
#include <openssl/rand.h>  // NOLINT(build/include_order)
#include <openssl/sha.h>   // NOLINT(build/include_order)
#include <openssl/ssl.h>   // NOLINT(build/include_order)

namespace fptn::protocol::tls {

std::string GetSHA1Hash(std::uint32_t number) {
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

std::string GenerateFptnKey(std::uint32_t timestamp) {
  std::string result = GetSHA1Hash(htonl(timestamp));
  if (result.size() > 4) {  //  key len
    return result.substr(0, 4);
  }
  throw boost::beast::system_error(
      boost::beast::error_code(static_cast<int>(::ERR_get_error()),
          boost::asio::error::get_ssl_category()),
      "Error generate Session ID");
}

bool SetHandshakeSessionID(SSL* ssl) {
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

bool IsFptnClientSessionID(
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

bool SetHandshakeSni(SSL* ssl, const std::string& sni) {
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

SSL_CTX* CreateNewSslCtx() {
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

std::string ChromeCiphers() {
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

}  // namespace fptn::protocol::tls
