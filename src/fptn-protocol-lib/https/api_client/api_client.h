/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include <nlohmann/json.hpp>
#include <openssl/ssl.h>  // NOLINT(build/include_order)

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"
#include "fptn-protocol-lib/https/obfuscator/socket/socket.h"

namespace fptn::protocol::https {

struct Response final {
  const std::string body;
  const int code;
  const std::string errmsg;

  Response(std::string b, int c, std::string e)
      : body(std::move(b)), code(c), errmsg(std::move(e)) {}

  nlohmann::json Json() const { return nlohmann::json::parse(body); }
};

using Headers = std::unordered_map<std::string, std::string>;
Headers RealBrowserHeaders(const std::string& host);

class ApiClient final {
 public:
  explicit ApiClient(const std::string& host,
      int port,
      obfuscator::IObfuscatorSPtr obfuscator);
  explicit ApiClient(std::string host,
      int port,
      std::string sni,
      obfuscator::IObfuscatorSPtr obfuscator);
  explicit ApiClient(std::string host,
      int port,
      std::string sni,
      std::string md5_fingerprint,
      obfuscator::IObfuscatorSPtr obfuscator);
  ~ApiClient() = default;

  Response Get(const std::string& handle, int timeout = 5);
  Response Post(const std::string& handle,
      const std::string& request,
      const std::string& content_type,
      int timeout = 5);

 protected:
  bool onVerifyCertificate(
      const std::string& md5_fingerprint, std::string& error) const;

  obfuscator::SocketSPtr CreateObfuscatedSocket(
      boost::asio::io_context& ioc) const;

 private:
  const std::string host_;
  const int port_;
  const std::string sni_;
  const std::string expected_md5_fingerprint_;
  const obfuscator::IObfuscatorSPtr obfuscator_;
};

using HttpsClientPtr = std::unique_ptr<ApiClient>;
}  // namespace fptn::protocol::https
