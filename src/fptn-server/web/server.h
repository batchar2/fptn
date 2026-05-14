/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

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
#include "common/jwt_token/token_manager.h"
#include "common/network/ip_packet.h"

#include "config/server_config.h"
#include "handshake/handshake_cache_manager.h"
#include "listener/listener.h"
#include "nat/table.h"
#include "user/user_manager.h"

namespace fptn::web {
class Server final {
 public:
  struct Config {
    std::uint16_t port;
    fptn::nat::TableSPtr nat_table;
    fptn::user::UserManagerSPtr user_manager;
    fptn::common::jwt_token::TokenManagerSPtr token_manager;
    fptn::statistic::MetricsSPtr prometheus;
    fptn::config::ServerConfigSPtr server_params;
  };

 public:
  Server(Config config, int thread_number = 8);
  ~Server();
  bool Start();
  bool Stop();

  fptn::web::SessionSPtr GetSessionById(fptn::ClientID client_id);

  fptn::common::network::BatchIPPacketPtr WaitForPackets(
      const std::chrono::milliseconds& duration);

 protected:
  // http
  int HandleApiDns(const http::request& req, http::response& resp) const;
  int HandleApiLogin(const http::request& req, http::response& resp) const;
  int HandleApiMetrics(const http::request& req, http::response& resp) const;
  int HandleApiTestFile(const http::request& req, http::response& resp) const;

 protected:
  // websocket
  fptn::client::SessionSPtr HandleWsOpenConnection(fptn::ClientID client_id,
      const fptn::common::network::IPv4Address& client_ip,
      const fptn::common::network::IPv4Address& client_vpn_ipv4,
      const fptn::common::network::IPv6Address& client_vpn_ipv6,
      const SessionSPtr& session,
      const std::string& url,
      const std::string& access_token);
  void HandleWsNewIPPacket(fptn::common::network::IPPacketPtr packet) noexcept;
  void HandleWsCloseConnection(fptn::ClientID client_id) noexcept;

 private:
  mutable std::shared_mutex mutex_;
  std::atomic<bool> running_;

  Config config_;
  const std::size_t thread_number_;

  boost::asio::io_context ioc_;
  fptn::common::data::ChannelPtr from_client_;

  ListenerSPtr listener_;

  HandshakeCacheManagerSPtr handshake_cache_manager_;

  std::vector<std::thread> ioc_threads_;
  std::unordered_map<fptn::ClientID, SessionSPtr> sessions_;
};

using ServerPtr = std::unique_ptr<Server>;
}  // namespace fptn::web
