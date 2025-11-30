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
#include <pcapplusplus/SSLHandshake.h>
#include <pcapplusplus/SSLLayer.h>
#include <spdlog/spdlog.h>

#include "common/network/resolv.h"

namespace {

std::optional<std::string> GetClientCacheKey(const std::string& sni,
    const std::vector<std::uint8_t>& client_handshake_data) {
  std::string cache_key;
  try {
    const bool is_ssl = pcpp::SSLLayer::IsSSLMessage(0, 0,
        const_cast<std::uint8_t*>(client_handshake_data.data()),
        client_handshake_data.size(), true);

    if (!client_handshake_data.empty() && is_ssl) {
      pcpp::SSLLayer* ssl_layer = pcpp::SSLLayer::createSSLMessage(
          const_cast<std::uint8_t*>(client_handshake_data.data()),
          client_handshake_data.size(), nullptr, nullptr);

      if (ssl_layer) {
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
        delete ssl_layer;
        if (!cache_key.empty()) {
          return cache_key;
        }
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_WARN("Failed to parse client handshake for cache key: {}", e.what());
  }
  return std::nullopt;
}

}  // namespace

namespace fptn::web {

HandshakeCacheManager::HandshakeCacheManager(
    boost::asio::io_context& ioc, std::chrono::seconds cache_ttl)
    : ioc_(ioc), cache_ttl_(cache_ttl) {}

HandshakeResponse HandshakeCacheManager::CheckCache(
    const std::string& cache_key) {
  const std::unique_lock<std::mutex> lock(mutex_);

  auto it = cache_.find(cache_key);
  if (it != cache_.end()) {
    const auto& entry = it->second;
    auto now = std::chrono::steady_clock::now();
    if (now - entry.timestamp < cache_ttl_) {
      return std::vector<std::uint8_t>(it->second.data);
    }
    cache_.erase(it);
  }
  return std::nullopt;
}

boost::asio::awaitable<HandshakeResponse> HandshakeCacheManager::GetHandshake(
    const std::string& sni,
    const std::vector<std::uint8_t>& client_handshake_data,
    const std::chrono::seconds& timeout) {
  const auto cache_key_opt = GetClientCacheKey(sni, client_handshake_data);

  if (!cache_key_opt.has_value()) {
    SPDLOG_WARN(
        "Failed to generate cache key for SNI: {}, using fallback", sni);
    co_return std::nullopt;
  }

  const std::string& cache_key = cache_key_opt.value();

  const auto cached_response = CheckCache(cache_key);
  if (cached_response.has_value()) {
    SPDLOG_INFO(
        "Cache hit for SNI: {} (TLS fingerprint key: {})", sni, cache_key);
    co_return std::vector<std::uint8_t>(*cached_response);  // copy
  }

  const auto response =
      co_await FetchRealHandshake(sni, client_handshake_data, timeout);

  if (response.has_value()) {
    const std::unique_lock<std::mutex> lock(mutex_);  // mutex

    cache_[cache_key] = CacheEntry{.data = response.value(),
        .timestamp = std::chrono::steady_clock::now()};
    SPDLOG_INFO(
        "Cached handshake response for SNI: {} (TLS fingerprint key: {}), "
        "size: {} bytes",
        sni, cache_key, response.value().size());
  } else {
    SPDLOG_WARN("Failed to fetch handshake from real server for SNI: {}", sni);
  }
  co_return std::vector<std::uint8_t>(*response);
}

boost::asio::awaitable<HandshakeResponse>
HandshakeCacheManager::FetchRealHandshake(const std::string& sni,
    const std::vector<std::uint8_t>& client_handshake_data,
    const std::chrono::seconds& timeout) const {
  boost::asio::ip::tcp::socket target_socket(ioc_);
  std::vector<std::uint8_t> full_response;
  boost::system::error_code ec;

  try {
    // DNS resolution
    boost::asio::io_context resolve_ioc;
    auto resolve_result = fptn::common::network::ResolveWithTimeout(
        resolve_ioc, sni, "443", static_cast<int>(timeout.count()));

    if (!resolve_result.success()) {
      SPDLOG_ERROR(
          "DNS failed for {}: {}", sni, resolve_result.error.message());
      co_return std::nullopt;
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
    std::size_t total_bytes = 0;

    while (total_bytes < kMaxSize) {
      const std::size_t bytes_read =
          co_await target_socket.async_read_some(boost::asio::buffer(buffer),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));

      full_response.insert(
          full_response.end(), buffer.begin(), buffer.begin() + bytes_read);
      total_bytes += bytes_read;
      if (ec || !bytes_read) {
        SPDLOG_INFO("EC> {} {}", ec.what(), bytes_read);
        break;
      }
    }
    SPDLOG_INFO("Received {} bytes from {}", total_bytes, sni);
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Error fetching handshake from {}: {}", sni, e.what());
  }

  target_socket.close(ec);

  if (!full_response.empty()) {
    co_return full_response;
  }

  co_return std::nullopt;
}

}  // namespace fptn::web
