/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <utility>

#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::common::network {

inline bool IsIpAddress(const std::string& host) {
  boost::system::error_code ec;
  boost::asio::ip::make_address(host, ec);
  return !ec;
}

struct ResolveResult {
  boost::system::error_code error;
  boost::asio::ip::tcp::resolver::results_type results;

  bool success() const { return !error; }
  explicit operator bool() const { return success(); }
};

inline ResolveResult ResolveWithTimeout(boost::asio::io_context& ioc,
    const std::string& host,
    const std::string& port,
    int timeout_seconds) {
  boost::asio::ip::tcp::resolver resolver(ioc);
  ResolveResult result;

  if (IsIpAddress(host)) {
    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(host, ec);
    if (ec) {
      result.error = ec;
      SPDLOG_ERROR(
          "DNS resolution - Invalid IP address {}: {}", host, ec.message());
      return result;
    }

    std::uint16_t port_num = 0;
    try {
      port_num = static_cast<std::uint16_t>(std::stoi(port));
    } catch (const std::exception& e) {
      result.error =
          boost::system::error_code(boost::system::errc::invalid_argument,
              boost::system::system_category());
      SPDLOG_ERROR(
          "DNS resolution - Invalid port number {}: {}", port, e.what());
      return result;
    }

    boost::asio::ip::tcp::endpoint endpoint(address, port_num);
    result.results = boost::asio::ip::tcp::resolver::results_type::create(
        endpoint, host, port);
    return result;
  }

  boost::asio::deadline_timer timer(ioc);
  timer.expires_from_now(boost::posix_time::seconds(timeout_seconds));

  bool operation_completed = false;

  resolver.async_resolve(host, port,
      [&](const boost::system::error_code& ec,
          boost::asio::ip::tcp::resolver::results_type results_) {
        if (!operation_completed) {
          result.error = ec;
          if (!ec) {
            result.results = results_;
          } else {
            SPDLOG_ERROR("DNS resolution - Failed for {}:{}: {}", host, port,
                ec.message());
          }
          operation_completed = true;
          timer.cancel();
        }
      });

  timer.async_wait([&](const boost::system::error_code& ec) {
    if (!ec && !operation_completed) {
      SPDLOG_WARN("DNS resolution - Timeout for {}:{} after {}s", host, port,
          timeout_seconds);
      resolver.cancel();
      result.error = boost::asio::error::timed_out;
      operation_completed = true;
    }
  });

  ioc.restart();
  while (!operation_completed) {
    ioc.run_one();
  }
  return result;
}

}  // namespace fptn::common::network
