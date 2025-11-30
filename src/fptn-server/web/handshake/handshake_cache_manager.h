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

using HandshakeResponse = std::optional<std::vector<std::uint8_t>>;

class HandshakeCacheManager {
 public:
  explicit HandshakeCacheManager(boost::asio::io_context& ioc,
      std::chrono::seconds cache_ttl = std::chrono::seconds(60));

  boost::asio::awaitable<HandshakeResponse> GetHandshake(const std::string& sni,
      const std::vector<std::uint8_t>& client_handshake_data,
      const std::chrono::seconds& timeout = std::chrono::seconds(5));

 protected:
  boost::asio::awaitable<HandshakeResponse> FetchRealHandshake(
      const std::string& sni,
      const std::vector<std::uint8_t>& client_handshake_data,
      const std::chrono::seconds& timeout) const;

  HandshakeResponse CheckCache(const std::string& cache_key);

 private:
  struct CacheEntry {
    std::vector<std::uint8_t> data;
    std::chrono::steady_clock::time_point timestamp;
  };

  mutable std::mutex mutex_;

  boost::asio::io_context& ioc_;
  std::chrono::seconds cache_ttl_;

  std::unordered_map<std::string, CacheEntry> cache_;
};

using HandshakeCacheManagerSPtr = std::shared_ptr<HandshakeCacheManager>;

}  // namespace fptn::web
