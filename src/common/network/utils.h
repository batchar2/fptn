/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>

#include "common/system/command.h"

namespace fptn::common::network {

inline std::vector<std::string> GetServerIpAddresses() {
  std::vector<std::string> cmd_stdout;
  fptn::common::system::command::run(
      "ip -o addr show | awk '{print $4}' | cut -d'/' -f1", cmd_stdout);
  return cmd_stdout;
}

std::size_t DrainSocket(boost::asio::ip::tcp::socket& socket) {
  boost::system::error_code ec;
  std::size_t total_drained = 0;

  const bool was_blocking = socket.non_blocking();
  try {
    socket.non_blocking(true, ec);
    if (ec) {
      SPDLOG_WARN(
          "Failed to set socket non-blocking for drain: {}", ec.message());
      return 0;
    }

    std::array<std::uint8_t, 16384> drain_buf{};
    while (true) {
      const size_t drained =
          socket.read_some(boost::asio::buffer(drain_buf), ec);

      if (ec) {
        if (ec == boost::asio::error::would_block ||
            ec == boost::asio::error::eof) {
          break;
        }
        SPDLOG_WARN("Error during socket drain: {}", ec.message());
        break;
      }
      if (drained == 0) {
        break;
      }
      total_drained += drained;
    }
  } catch (const std::exception& e) {
    SPDLOG_ERROR("Exception during socket drain: {}", e.what());
  }
  socket.non_blocking(was_blocking, ec);
  if (ec) {
    SPDLOG_WARN("Failed to restore socket blocking mode: {}", ec.message());
  }
  return total_drained;
}

}  // namespace fptn::common::network
