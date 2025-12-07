/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "web/handshake/handshake_cache_manager.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast.hpp>
#include <pcapplusplus/SSLHandshake.h>  // NOLINT(build/include_order)
#include <pcapplusplus/SSLLayer.h>      // NOLINT(build/include_order)
#include <spdlog/spdlog.h>              // NOLINT(build/include_order)

#include "common/network/resolv.h"

namespace {

std::string GetClientCacheKey(const std::string& sni,
    const std::vector<std::uint8_t>& client_handshake_data) {
  try {
    const bool is_ssl = pcpp::SSLLayer::IsSSLMessage(0, 0,
        const_cast<std::uint8_t*>(client_handshake_data.data()),
        client_handshake_data.size(), true);

    if (!client_handshake_data.empty() && is_ssl) {
      pcpp::SSLLayer* ssl_layer = pcpp::SSLLayer::createSSLMessage(
          const_cast<std::uint8_t*>(client_handshake_data.data()),
          client_handshake_data.size(), nullptr, nullptr);

      if (ssl_layer) {
        std::string cache_key;
        auto* handshake = dynamic_cast<pcpp::SSLHandshakeLayer*>(ssl_layer);
        if (handshake) {
          auto* hello =
              handshake
                  ->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>();
          if (hello) {
            auto fingerprint = hello->generateTLSFingerprint();
            cache_key = sni + ":" + fingerprint.toMD5();
          }
        }
        if (!cache_key.empty()) {
          return cache_key;
        }
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_WARN("Failed to parse client handshake for cache key: {}", e.what());
  }
  return {};
}

}  // namespace

namespace fptn::web {

HandshakeCacheManager::HandshakeCacheManager(
    boost::asio::io_context& ioc, std::chrono::seconds cache_ttl)
    : ioc_(ioc), cache_ttl_(cache_ttl) {}

HandshakeResponse HandshakeCacheManager::CheckCache(
    const std::string& cache_key) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  auto it = cache_.find(cache_key);
  if (it != cache_.end()) {
    const auto& entry = it->second;
    const auto now = std::chrono::steady_clock::now();
    if (now - entry.timestamp < cache_ttl_) {
      return it->second.data;
    }
    cache_.erase(it);
  }
  return nullptr;
}

boost::asio::awaitable<HandshakeResponse> HandshakeCacheManager::GetHandshake(
    const std::string& sni,
    const std::uint8_t* buffer_ptr,
    std::size_t size,
    const std::chrono::seconds& timeout) {
  // doesnt work
  std::vector<std::uint8_t> client_handshake_data(
      buffer_ptr, buffer_ptr + size);
  const auto cache_key = GetClientCacheKey(sni, client_handshake_data);

  if (cache_key.empty()) {
    SPDLOG_WARN(
        "Failed to generate cache key for SNI: {}, using fallback", sni);
    co_return nullptr;
  }

  SPDLOG_INFO("fingerprint key: {}) ", cache_key);
  const auto cached_response = CheckCache(cache_key);
  if (cached_response) {
    SPDLOG_INFO(
        "Cache hit for SNI: {} (TLS fingerprint key: {})", sni, cache_key);
    co_return cached_response;
  }

  const auto response =
      co_await FetchRealHandshake(sni, client_handshake_data, timeout);
  if (response) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex
    cache_[cache_key] = CacheEntry{
        .data = response, .timestamp = std::chrono::steady_clock::now()};
    SPDLOG_INFO(
        "Cached handshake response for SNI: {} (TLS fingerprint key: {}), "
        "size: {} bytes",
        sni, cache_key, response->size());
    co_return response;
  }
  SPDLOG_WARN("Failed to fetch handshake from real server for SNI: {}", sni);
  co_return HandshakeResponse();
}

boost::asio::awaitable<HandshakeResponse>
HandshakeCacheManager::FetchRealHandshake(const std::string& sni,
    const std::vector<std::uint8_t>& client_handshake_data,
    const std::chrono::seconds& timeout) const {
  boost::asio::ip::tcp::socket target_socket(ioc_);
  auto full_response = std::make_shared<std::vector<std::uint8_t>>();
  boost::system::error_code ec;

  try {
    // DNS resolution
    boost::asio::io_context resolve_ioc;
    const auto resolve_result = fptn::common::network::ResolveWithTimeout(
        resolve_ioc, sni, "443", timeout.count());

    if (!resolve_result.success()) {
      SPDLOG_ERROR(
          "DNS failed for {}: {}", sni, resolve_result.error.message());
      co_return nullptr;
    }

    // Connect to real server
    co_await boost::asio::async_connect(
        target_socket, resolve_result.results, boost::asio::use_awaitable);
    // Send client handshake
    co_await boost::asio::async_write(target_socket,
        boost::asio::buffer(client_handshake_data), boost::asio::use_awaitable);
    co_await boost::asio::steady_timer(ioc_, std::chrono::milliseconds(200))
        .async_wait(boost::asio::use_awaitable);

    constexpr std::size_t kMaxSize = 16384;
    std::array<std::uint8_t, kMaxSize> buffer{};
    const std::size_t bytes_read =
        co_await target_socket.async_read_some(boost::asio::buffer(buffer),
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));

    if (bytes_read) {
      full_response->insert(
          full_response->end(), buffer.begin(), buffer.begin() + bytes_read);
    }
    SPDLOG_INFO("Received {} bytes from {}", bytes_read, sni);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error fetching handshake from {}: {}", sni, e.what());
  }
  target_socket.close(ec);

  if (!full_response->empty()) {
    co_return full_response;
  }
  co_return nullptr;
}

}  // namespace fptn::web
