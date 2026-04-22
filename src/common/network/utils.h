/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <openssl/bio.h>    // NOLINT(build/include_order)
#include <openssl/ssl.h>    // NOLINT(build/include_order)
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#ifndef __ANDROID__
#include "common/system/command.h"
#endif

namespace fptn::common::network {

#ifndef __ANDROID__
  inline std::vector<std::string> GetServerIpAddresses() {
    std::vector<std::string> cmd_stdout;
    fptn::common::system::command::run(
            "ip -o addr show | awk '{print $4}' | cut -d'/' -f1", cmd_stdout);
    return cmd_stdout;
  }
#endif

inline void CleanSocket(boost::asio::ip::tcp::socket& socket) {
  try {
    while (socket.available() != 0) {
      boost::system::error_code ec;
      std::array<std::uint8_t, 4096> buffer{};

      const std::size_t bytes =
          socket.read_some(boost::asio::buffer(buffer), ec);
      (void)bytes;
      if (ec == boost::asio::error::eof) {
        break;
      }
      if (ec) {
        SPDLOG_ERROR("Socket error: {}", ec.message());
        break;
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception: {}", e.what());
  }
}

inline bool CleanSsl(const SSL* ssl) {
  if (ssl == nullptr) {
    return false;
  }
  if (BIO* rb = SSL_get_rbio(ssl)) {
    BIO_flush(rb);
    char buf[4096] = {};
    while (BIO_pending(rb) > 0) {
      BIO_read(rb, buf, sizeof(buf));
    }
  }
  return true;
}

inline bool IsServerHelloComplete(const std::vector<uint8_t>& data) {
  if (data.size() < 5) {
    SPDLOG_INFO(
        "IsServerHelloComplete: data too small ({} bytes)", data.size());
    return false;
  }

  std::size_t pos = 0;
  bool found_server_hello = false;
  bool is_tls13 = false;
  bool handshake_done = false;

  while (pos + 5 <= data.size()) {
    const std::uint8_t content_type = data[pos];
    const std::uint16_t record_len = (data[pos + 3] << 8) | data[pos + 4];

    if (pos + 5 + record_len > data.size()) {
      return false;
    }

    if (content_type == 22) {  // Handshake
      std::size_t hpos = pos + 5;
      std::size_t hend = hpos + record_len;

      while (hpos + 4 <= hend) {
        const std::uint8_t msg_type = data[hpos];
        const std::uint32_t msg_len =
            (data[hpos + 1] << 16) | (data[hpos + 2] << 8) | data[hpos + 3];

        if (hpos + 4 + msg_len > hend) {
          SPDLOG_INFO(
              "IsServerHelloComplete: incomplete handshake message at pos {}",
              hpos);
          return false;
        }

        if (msg_type == 2) {  // ServerHello
          found_server_hello = true;
          if (hpos + 4 + 2 <= data.size()) {
            const std::uint16_t version =
                (data[hpos + 4 + 2] << 8) | data[hpos + 4 + 3];
            is_tls13 = (version != 0x0303);
            SPDLOG_INFO(
                "IsServerHelloComplete: ServerHello found, TLS version "
                "0x{:04x}, is_tls13={}",
                version, is_tls13);
          } else {
            SPDLOG_INFO(
                "IsServerHelloComplete: ServerHello found but version field "
                "missing");
          }
        }

        // TLS 1.2: ServerHelloDone
        if (found_server_hello && !is_tls13 && msg_type == 14) {
          handshake_done = true;
          SPDLOG_INFO(
              "IsServerHelloComplete: ServerHelloDone (TLS 1.2) detected, "
              "handshake complete");
        }

        // TLS 1.3: Finished
        if (found_server_hello && is_tls13 && msg_type == 20) {
          handshake_done = true;
          SPDLOG_INFO(
              "IsServerHelloComplete: Finished (TLS 1.3) detected, handshake "
              "complete");
        }

        hpos += 4 + msg_len;
      }
    }

    // TLS 1.3: Application Data (23) или ChangeCipherSpec (20)
    // Finished
    if (found_server_hello && is_tls13 && !handshake_done &&
        (content_type == 20 || content_type == 23)) {
      if (pos + 5 + record_len >= data.size()) {
        handshake_done = true;
        SPDLOG_INFO(
            "IsServerHelloComplete: TLS 1.3 {} record ends the handshake",
            content_type == 20 ? "ChangeCipherSpec" : "ApplicationData");
      }
    }

    pos += 5 + record_len;
  }

  if (found_server_hello && handshake_done) {
    SPDLOG_INFO("IsServerHelloComplete: handshake complete, total size={}",
        data.size());
  } else if (found_server_hello && !handshake_done) {
    SPDLOG_INFO(
        "IsServerHelloComplete: ServerHello found but handshake not yet done, "
        "size={}",
        data.size());
  } else {
    SPDLOG_INFO(
        "IsServerHelloComplete: ServerHello not found, size={}", data.size());
  }

  return found_server_hello && handshake_done;
}

inline bool IsClientHelloComplete(const std::vector<uint8_t>& data) {
  if (data.size() < 5) {
    return false;
  }

  std::size_t pos = 0;
  while (pos + 5 <= data.size()) {
    const std::uint8_t content_type = data[pos];
    const std::uint16_t record_length = (data[pos + 3] << 8) | data[pos + 4];

    if (pos + 5 + record_length > data.size()) {
      return false;
    }

    if (content_type == 22) {  // Handshake
      std::size_t handshake_pos = pos + 5;
      std::size_t handshake_end = handshake_pos + record_length;

      while (handshake_pos + 4 <= handshake_end) {
        const std::uint8_t msg_type = data[handshake_pos];
        const std::uint32_t msg_length = (data[handshake_pos + 1] << 16) |
                                         (data[handshake_pos + 2] << 8) |
                                         data[handshake_pos + 3];
        if (handshake_pos + 4 + msg_length > handshake_end) {
          return false;
        }
        if (msg_type == 1) {  // ClientHello
          return true;
        }
        handshake_pos += 4 + msg_length;
      }
    }
    pos += 5 + record_length;
  }
  return false;
}


using TlsData = std::optional<std::vector<std::uint8_t>>;

inline TlsData WaitForServerTlsHello(boost::asio::ip::tcp::socket& socket,
    const std::chrono::milliseconds drain_timeout = std::chrono::milliseconds(
        5000)) {
  std::vector<std::uint8_t> data;
  data.reserve(65536);

  const auto start_time = std::chrono::steady_clock::now();

  try {
    boost::system::error_code ec;
    std::array<std::uint8_t, 4096> buffer{};

    while (std::chrono::steady_clock::now() - start_time < drain_timeout) {
      if (socket.available() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        continue;
      }

      const std::size_t bytes =
          socket.read_some(boost::asio::buffer(buffer), ec);

      if (bytes) {
        data.insert(data.end(), buffer.begin(), buffer.begin() + bytes);
        if (IsServerHelloComplete(data)) {
          return data;
        }
      }

      if (ec == boost::asio::error::eof) {
        break;
      }
      if (ec) {
        SPDLOG_ERROR("Socket error: {}", ec.message());
        break;
      }
    }
    SPDLOG_WARN(
        "Timeout waiting for server hello, total data: {} bytes", data.size());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception: {}", e.what());
  }
  return std::nullopt;
}

inline boost::asio::awaitable<TlsData> WaitForServerTlsHelloAsync(
    boost::asio::ip::tcp::socket& socket,
    const std::chrono::milliseconds drain_timeout = std::chrono::milliseconds(
        5000)) {
  std::vector<std::uint8_t> data;
  data.reserve(65536);

  try {
    boost::system::error_code ec;
    std::array<std::uint8_t, 4096> buffer{};
    const auto start_time = std::chrono::steady_clock::now();
    int packet_count = 0;

    while (std::chrono::steady_clock::now() - start_time < drain_timeout) {
      if (socket.available() == 0) {
        boost::asio::steady_timer timer(
            co_await boost::asio::this_coro::executor,
            std::chrono::milliseconds(10));
        co_await timer.async_wait(boost::asio::use_awaitable);
        continue;
      }

      const std::size_t bytes =
          co_await socket.async_read_some(boost::asio::buffer(buffer),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));

      packet_count++;

      if (bytes) {
        data.insert(data.end(), buffer.begin(), buffer.begin() + bytes);
        if (IsServerHelloComplete(data)) {
          SPDLOG_INFO(
              "Server hello complete after {} packets, total size: {} bytes",
              packet_count, data.size());
          co_return data;
        }
      }

      if (ec == boost::asio::error::eof) {
        SPDLOG_INFO(
            "Connection closed by server, total data: {} bytes", data.size());
        break;
      }
      if (ec) {
        SPDLOG_ERROR("Socket error: {}", ec.message());
        break;
      }
    }
    SPDLOG_WARN(
        "Timeout waiting for server hello, total data: {} bytes", data.size());
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception: {}", e.what());
  }
  co_return std::nullopt;
}

inline boost::asio::awaitable<TlsData> WaitForClientTlsHelloAsync(
    boost::asio::ip::tcp::socket& socket,
    const std::chrono::milliseconds drain_timeout = std::chrono::milliseconds(
        1000)) {
  std::vector<std::uint8_t> data;
  data.reserve(65536);

  try {
    boost::system::error_code ec;
    std::array<std::uint8_t, 4096> buffer{};
    const auto start_time = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start_time < drain_timeout) {
      if (socket.available() == 0) {
        boost::asio::steady_timer timer(
            co_await boost::asio::this_coro::executor,
            std::chrono::milliseconds(10));
        co_await timer.async_wait(boost::asio::use_awaitable);
        continue;
      }

      const std::size_t bytes =
          co_await socket.async_read_some(boost::asio::buffer(buffer),
              boost::asio::redirect_error(boost::asio::use_awaitable, ec));
      if (bytes) {
        data.insert(data.end(), buffer.begin(), buffer.begin() + bytes);
        if (IsClientHelloComplete(data)) {
          co_return data;
        }
      }

      if (ec == boost::asio::error::eof) {
        break;
      }
      if (ec) {
        SPDLOG_ERROR("Socket error during drain: {}", ec.message());
        break;
      }
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during socket drain: {}", e.what());
  }
  co_return std::nullopt;
}

}  // namespace fptn::common::network
