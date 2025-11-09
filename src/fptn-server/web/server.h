/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include "common/data/channel.h"
#include "common/data/channel_async.h"
#include "common/jwt_token/token_manager.h"
#include "common/network/ip_packet.h"

#include "listener/listener.h"
#include "nat/table.h"
#include "user/user_manager.h"

namespace fptn::web {
class Server final {
 public:
  Server(std::uint16_t port,
      const fptn::nat::TableSPtr& nat_table,
      const fptn::user::UserManagerSPtr& user_manager,
      const fptn::common::jwt_token::TokenManagerSPtr& token_manager,
      const fptn::statistic::MetricsSPtr& prometheus,
      const std::string& prometheus_access_key,
      fptn::common::network::IPv4Address dns_server_ipv4,
      fptn::common::network::IPv6Address dns_server_ipv6,
      bool enable_detect_probing,
      std::size_t max_active_sessions_per_user,
      int thread_number = 8);
  ~Server();
  bool Start();
  bool Stop();

  void Send(fptn::common::network::IPPacketPtr packet);
  fptn::common::network::IPPacketPtr WaitForPacket(
      const std::chrono::milliseconds& duration);

 protected:
  boost::asio::awaitable<void> RunSender();

 protected:
  // http
  int HandleApiDns(const http::request& req, http::response& resp);
  int HandleApiLogin(const http::request& req, http::response& resp);
  int HandleApiMetrics(const http::request& req, http::response& resp);
  int HandleApiTestFile(const http::request& req, http::response& resp);

 protected:
  // websocket
  bool HandleWsOpenConnection(fptn::ClientID client_id,
      const fptn::common::network::IPv4Address& client_ip,
      const fptn::common::network::IPv4Address& client_vpn_ipv4,
      const fptn::common::network::IPv6Address& client_vpn_ipv6,
      const SessionSPtr& session,
      const std::string& url,
      const std::string& access_token);
  void HandleWsNewIPPacket(fptn::common::network::IPPacketPtr packet) noexcept;
  void HandleWsCloseConnection(fptn::ClientID client_id) noexcept;

 private:
  const std::string kUrlDns_ = "/api/v1/dns";
  const std::string kUrlLogin_ = "/api/v1/login";
  const std::string kUrlMetrics_ = "/api/v1/metrics";
  const std::string kUrlTestFileBin_ = "/api/v1/test/file.bin";
  const std::string kUrlWebSocket_ = "/fptn";

  mutable std::mutex mutex_;
  std::atomic<bool> running_;

  const std::uint16_t port_;
  const fptn::nat::TableSPtr& nat_table_;
  const fptn::user::UserManagerSPtr& user_manager_;
  const fptn::common::jwt_token::TokenManagerSPtr token_manager_;
  const fptn::statistic::MetricsSPtr& prometheus_;
  const std::string prometheus_access_key_;
  const fptn::common::network::IPv4Address dns_server_ipv4_;
  const fptn::common::network::IPv6Address dns_server_ipv6_;
  const bool enable_detect_probing_;
  const std::size_t max_active_sessions_per_user_;
  const std::size_t thread_number_;

  boost::asio::io_context ioc_;
  fptn::common::data::ChannelPtr from_client_;
  fptn::common::data::ChannelAsyncPtr to_client_;

  ListenerSPtr listener_;

  std::vector<std::thread> ioc_threads_;
  std::unordered_map<fptn::ClientID, SessionSPtr> sessions_;
};

using ServerPtr = std::unique_ptr<Server>;
}  // namespace fptn::web
