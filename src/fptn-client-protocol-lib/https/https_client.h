/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>  // NOLINT(build/include_order)

namespace fptn::client::protocol::lib::https {

using Headers = std::unordered_map<std::string, std::string>;

struct Response final {
  const std::string body;
  const int code;
  const std::string errmsg;

  Response(std::string b, int c, std::string e)
      : body(std::move(b)), code(c), errmsg(std::move(e)) {}

  nlohmann::json Json() const { return nlohmann::json::parse(body); }
};

class HttpsClient final {
 public:
  static std::string GetSHA1Hash(std::uint32_t number);
  static std::string GenerateFptnKey(std::uint32_t timestamp);
  static bool SetHandshakeSessionID(SSL* ssl);
  static bool IsFptnClientSessionID(
      const std::uint8_t* session, std::size_t session_len);
  static bool SetHandshakeSni(SSL* ssl, const std::string& sni);
  static SSL_CTX* CreateNewSslCtx();
  static std::string ChromeCiphers();
  static Headers RealBrowserHeaders(const std::string& host, int port);

  explicit HttpsClient(const std::string& host, int port);
  explicit HttpsClient(std::string host, int port, std::string sni);
  Response Get(const std::string& handle, int timeout = 5);
  Response Post(const std::string& handle,
      const std::string& request,
      const std::string& content_type,
      int timeout = 5);

 private:
  const std::string host_;
  const int port_;
  const std::string sni_;
};

using HttpsClientPtr = std::unique_ptr<HttpsClient>;
}  // namespace fptn::client::protocol::lib::https
