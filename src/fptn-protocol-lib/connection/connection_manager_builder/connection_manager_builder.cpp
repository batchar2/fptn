/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/connection/connection_manager_builder/connection_manager_builder.h"

namespace fptn::protocol::connection {

ConnectionManagerBuilder::ConnectionManagerBuilder() : config_{} {}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetConnectionStrategyType(
    strategies::ConnectionStrategy connection_strategy_type) {
  connection_strategy_type_ = connection_strategy_type;
  return *this;
}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetServer(
    const IPv4Address& ip, int port) {
  config_.common.server_ip = ip;
  config_.common.server_port = port;
  return *this;
}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetSNI(
    const std::string& sni) {
  config_.common.sni = sni;
  return *this;
}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetServerFingerprint(
    const std::string& md5_fingerprint) {
  config_.common.md5_fingerprint = md5_fingerprint;
  return *this;
}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetTunInterface(
    const IPv4Address& ipv4, const IPv6Address& ipv6) {
  config_.common.tun_interface_address_ipv4 = ipv4;
  config_.common.tun_interface_address_ipv6 = ipv6;
  return *this;
}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetCensorshipStrategy(
    fptn::protocol::https::HttpsInitConnectionStrategy strategy) {
  config_.common.https_init_connection_strategy = strategy;
  return *this;
}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetOnConnectedCallback(
    const fptn::protocol::https::OnConnectedCallback& callback) {
  config_.common.on_connected_callback = callback;
  return *this;
}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetMaxReconnections(
    int max_attempts) {
  config_.common.max_reconnections = max_attempts;
  return *this;
}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetPoolSize(
    std::size_t pool_size) {
  config_.pool.size = pool_size;
  return *this;
}

ConnectionManagerBuilder& ConnectionManagerBuilder::SetConnectionTimeout(
    int timeout_ms) {
  config_.common.connection_timeout_ms = timeout_ms;
  return *this;
}

ConnectionManagerPtr ConnectionManagerBuilder::Build() {
  return std::make_unique<ConnectionManager>(
      connection_strategy_type_, config_);
}

}  // namespace fptn::protocol::connection
