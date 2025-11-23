/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

#include "fptn-protocol-lib/https/obfuscator/methods/obfuscator_interface.h"

namespace fptn::protocol::https {

struct Response final {
  std::string body;
  int code;
  std::string errmsg;

  Response() : code(600) {}

  Response(std::string b, int c, std::string e)
      : body(std::move(b)), code(c), errmsg(std::move(e)) {}

  Response(const Response& other)
      : body(other.body), code(other.code), errmsg(other.errmsg) {}

  Response& operator=(const Response& other) {
    if (this != &other) {
      this->~Response();
      new (this) Response(other);
    }
    return *this;
  }

  Response(Response&& other) = delete;
  Response& operator=(Response&& other) = delete;

  nlohmann::json Json() const { return nlohmann::json::parse(body); }
};

class ApiClient {
 public:
  ApiClient(const std::string& host,
      int port,
      obfuscator::IObfuscatorSPtr obfuscator = nullptr);

  ApiClient(std::string host,
      int port,
      std::string sni,
      obfuscator::IObfuscatorSPtr obfuscator = nullptr);

  ApiClient(std::string host,
      int port,
      std::string sni,
      std::string md5_fingerprint,
      obfuscator::IObfuscatorSPtr obfuscator = nullptr);

  Response Get(const std::string& handle, int timeout = 30) const;
  Response Post(const std::string& handle,
      const std::string& request,
      const std::string& content_type = "application/json",
      int timeout = 30) const;
  bool TestHandshake(int timeout = 30) const;

 protected:
  ApiClient Clone() const;

  Response GetImpl(const std::string& handle, int timeout) const;

  Response PostImpl(const std::string& handle,
      const std::string& request,
      const std::string& content_type,
      int timeout) const;

  bool TestHandshakeImpl(int timeout) const;

  bool onVerifyCertificate(
      const std::string& md5_fingerprint, std::string& error) const;

 private:
  std::string host_;
  int port_;
  std::string sni_;
  std::string expected_md5_fingerprint_;
  obfuscator::IObfuscatorSPtr obfuscator_;
};

using HttpsClientPtr = std::unique_ptr<ApiClient>;

}  // namespace fptn::protocol::https
