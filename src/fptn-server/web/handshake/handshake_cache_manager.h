/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>

namespace fptn::web {

using HandshakeResponse = std::shared_ptr<std::vector<std::uint8_t>>;
// using OptionalHandshakeResponse = std::optional<HandshakeResponse>;

class HandshakeCacheManager final {
 public:
  explicit HandshakeCacheManager(boost::asio::io_context& ioc,
      std::chrono::seconds cache_ttl = std::chrono::seconds(180));

  boost::asio::awaitable<HandshakeResponse> GetHandshake(const std::string& sni,
      const std::uint8_t* buffer_ptr,
      std::size_t size,
      const std::chrono::seconds& timeout);

 protected:
  boost::asio::awaitable<HandshakeResponse> FetchRealHandshake(
      const std::string& sni,
      const std::vector<std::uint8_t>& client_handshake_data,
      const std::chrono::seconds& timeout) const;

  HandshakeResponse CheckCache(const std::string& cache_key);

 private:
  struct CacheEntry {
    HandshakeResponse data;
    std::chrono::steady_clock::time_point timestamp;
  };

  mutable std::mutex mutex_;

  boost::asio::io_context& ioc_;
  std::chrono::seconds cache_ttl_;

  std::unordered_map<std::string, CacheEntry> cache_;
};

using HandshakeCacheManagerSPtr = std::shared_ptr<HandshakeCacheManager>;

}  // namespace fptn::web
