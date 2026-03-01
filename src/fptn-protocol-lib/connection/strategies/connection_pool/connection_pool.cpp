/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/strategies/connection_pool/connection_pool.h"

#include <shared_mutex>

#include "common/utils/uuid4.h"

namespace {

bool RemoveFromConnectionList(
    fptn::protocol::connection::strategies::ConnectionList& connections,
    const std::uint64_t id) {
  for (auto it = connections.begin(); it != connections.end(); ++it) {
    if ((*it)->connection_id == id) {
      connections.erase(it);
      return true;
    }
  }
  return false;
}

}  // namespace

namespace fptn::protocol::connection::strategies {
ConnectionPool::ConnectionPool(std::string jwt_access_token,
    fptn::protocol::https::ConnectionConfig config)
    : BaseStrategyConnection(std::move(jwt_access_token), std::move(config)),
      session_id_(common::utils::GenerateUUID4()) {
  std::random_device rd;
  random_generator_.seed(rd());
}

ConnectionPool::~ConnectionPool() {
  Stop();  // NOLINT
}

void ConnectionPool::Start() {
  SetRunningStatus(true);
  boost::asio::co_spawn(
      GetIOContext(),
      [this]() -> boost::asio::awaitable<void> {
        co_await ManagePoolCoroutine();
      },
      boost::asio::detached);
  RunEventLoop();
}

void ConnectionPool::Stop() {
  const std::unique_lock lock(mutex_);  // mutex

  SetRunningStatus(false);
  for (auto& ctx : all_connections_) {
    if (ctx && ctx->client) {
      ctx->status = ConnectionStatus::kError;
      ctx->client->Stop();
    }
  }

  all_connections_.clear();
  sending_data_connections_.clear();
  getting_data_connections_.clear();
}

bool ConnectionPool::Send(fptn::common::network::IPPacketPtr packet) {
  if (!IsStarted()) {
    return false;
  }

  std::shared_ptr<ConnectionContext> connection;
  {
    const std::shared_lock lock(mutex_);  // read-only lock

    if (sending_data_connections_.empty()) {
      return false;
    }
    const int random_index =
        GetRandomInt(0, sending_data_connections_.size() - 1);
    const int sender_index = random_index % sending_data_connections_.size();
    std::cerr << "sender_index>" << sender_index << "\n";
    connection = sending_data_connections_[sender_index];
  }
  return connection && connection->client->Send(std::move(packet));
}

bool ConnectionPool::IsStarted() { return RunningStatus(); }

boost::asio::awaitable<void> ConnectionPool::ManagePoolCoroutine() {
  boost::asio::steady_timer timer(GetIOContext());
  bool first_itteration = true;
  while (IsStarted()) {
    try {
      co_await boost::asio::post(boost::asio::use_awaitable);

      co_await RemoveExpiredConnections();

      co_await UpdateConnectionsStatus();

      co_await CreateMissingConnections();

      if (first_itteration) {
        first_itteration = false;
        auto config = Config();
        config.common.on_connected_callback();
      }
    } catch (const std::exception& e) {
      SPDLOG_ERROR("Error in ManagePoolCoroutine: {}", e.what());
    }
    timer.expires_after(std::chrono::milliseconds(100));
    co_await timer.async_wait(boost::asio::use_awaitable);
  }

  co_return;
}

boost::asio::awaitable<std::shared_ptr<ConnectionContext>>
ConnectionPool::CreateNewConnection(int sending_mode_seconds, int ttl_seconds) {
  try {
    auto connection =
        std::make_shared<ConnectionContext>(sending_mode_seconds, ttl_seconds);
    connection->status = ConnectionStatus::kCreating;

    auto config = Config();
    config.common.on_connected_callback = nullptr;

    connection->client =
        std::make_shared<fptn::protocol::https::WebsocketClient>(
            JWTAccessToken(), config, GetIOContext());

    connection->client->Run();
    co_await boost::asio::post(boost::asio::use_awaitable);

    boost::asio::steady_timer timer(GetIOContext());

    for (int i = 0; i < 10; i++) {
      if (connection->client->IsStarted()) {
        connection->status = ConnectionStatus::kCreating;
        SPDLOG_INFO("Connection #{} READY", connection->connection_id);
        co_return connection;
      }

      timer.expires_after(std::chrono::milliseconds(500));
      co_await timer.async_wait(boost::asio::use_awaitable);
    }
    connection->status = ConnectionStatus::kError;
    connection->client->Stop();
    SPDLOG_ERROR("Connection #{} FAILED to start", connection->connection_id);
  } catch (const std::exception& err) {
    SPDLOG_ERROR("Failed to create connection: {}", err.what());
  }
  co_return nullptr;
}

boost::asio::awaitable<void> ConnectionPool::RemoveExpiredConnections() {
  std::vector<std::shared_ptr<ConnectionContext>> dead_connections;
  {
    const std::unique_lock lock(mutex_);  // mutex

    for (auto it = all_connections_.begin(); it != all_connections_.end();) {
      auto& connection = *it;
      const bool dead = connection->IsExpired() ||
                        connection->status == ConnectionStatus::kError;
      if (dead) {
        dead_connections.push_back(connection);
        it = all_connections_.erase(it);

        // remove from other collections
        RemoveFromConnectionList(
            getting_data_connections_, connection->connection_id);
        RemoveFromConnectionList(
            sending_data_connections_, connection->connection_id);
      } else {
        ++it;
      }
    }
  }
  if (!dead_connections.empty()) {
    // close connection in background
    boost::asio::co_spawn(
        GetIOContext(),
        [closed_connections =
                std::move(dead_connections)]() -> boost::asio::awaitable<void> {
          for (const auto& connection : closed_connections) {
            if (connection && connection->client) {
              connection->client->Stop();
            }
          }
          co_return;
        },
        boost::asio::detached);
  }
  co_return;
}

boost::asio::awaitable<void> ConnectionPool::UpdateConnectionsStatus() {
  const std::unique_lock lock(mutex_);  // mutex

  const auto now = std::chrono::system_clock::now();

  for (auto& connection : all_connections_) {
    const ConnectionStatus old_status = connection->status;

    // change status
    if (connection->status == ConnectionStatus::kSending &&
        connection->SendTimeExpired()) {
      connection->status = ConnectionStatus::kReceiving;
    } else if (connection->status == ConnectionStatus::kCreating &&
               connection->client->IsStarted()) {
      if (connection->timings.send_mode_until > now) {
        connection->status = ConnectionStatus::kSending;
      } else {
        connection->status = ConnectionStatus::kReceiving;
      }
    }

    // move to collection
    if (old_status != connection->status) {
      RemoveFromConnectionList(
          sending_data_connections_, connection->connection_id);
      RemoveFromConnectionList(
          getting_data_connections_, connection->connection_id);

      if (connection->status == ConnectionStatus::kSending) {
        sending_data_connections_.push_back(connection);
        SPDLOG_INFO("Connection #{} moved to SENDING (until {})",
            connection->connection_id,
            std::chrono::duration_cast<std::chrono::seconds>(
                connection->timings.send_mode_until - now)
                .count());
      } else if (connection->status == ConnectionStatus::kReceiving) {
        getting_data_connections_.push_back(connection);
        SPDLOG_INFO(
            "Connection #{} moved to RECEIVING", connection->connection_id);
      }
    }
  }
  co_return;
}

boost::asio::awaitable<void> ConnectionPool::CreateMissingConnections() {
  if (!IsStarted()) {
    co_return;
  }

  int sending_count = 0;
  int receiving_count = 0;

  {
    const std::unique_lock lock(mutex_);  // mutex

    for (const auto& connection : all_connections_) {
      if (connection->status == ConnectionStatus::kSending &&
          connection->CanSend()) {
        sending_count++;
      }
      if (connection->status == ConnectionStatus::kReceiving &&
          !connection->IsExpired()) {
        receiving_count++;
      }
    }
  }

  const int target_per_type = std::max<int>(1, settings_.min_connections / 2);

  // Create sending connections
  if (sending_count < target_per_type) {
    const int need = target_per_type - sending_count;
    for (int i = 0; i < need; i++) {
      if (all_connections_.size() >= settings_.max_connections) {
        break;
      }
      const int send_time =
          GetRandomInt(settings_.sending_mode_range.min_seconds,
              settings_.sending_mode_range.max_seconds);
      const int ttl = GetRandomInt(settings_.connection_ttl_range.min_seconds,
          settings_.connection_ttl_range.max_seconds);
      auto connection = co_await CreateNewConnection(send_time, ttl);
      if (connection) {
        const std::unique_lock lock(mutex_);  // mutex

        all_connections_.push_back(std::move(connection));
      }
    }
  }

  // create receiving connections
  if (receiving_count < target_per_type) {
    const int need = target_per_type - receiving_count;
    for (int i = 0; i < need; i++) {
      if (all_connections_.size() >= settings_.max_connections) {
        break;
      }
      const int ttl = GetRandomInt(settings_.connection_ttl_range.min_seconds,
          settings_.connection_ttl_range.max_seconds);

      auto connection = co_await CreateNewConnection(0, ttl);
      if (connection) {
        const std::unique_lock lock(mutex_);  // mutex

        all_connections_.push_back(std::move(connection));
      }
    }
  }
  co_return;
}

int ConnectionPool::GetRandomInt(const int min, const int max) const {
  std::uniform_int_distribution<int> dist(min, max);
  return dist(random_generator_);
}

}  // namespace fptn::protocol::connection::strategies
