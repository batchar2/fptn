/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "nat/connection_multiplexer/connection_multiplexer.h"

#include <string>
#include <utility>

#include "fptn-server/nat/connect_params.h"

namespace fptn::nat {

ConnectionMultiplexer::ConnectionMultiplexer(const ConnectParams& params,
    IPv4Address fake_client_ipv4,
    IPv6Address fake_client_ipv6)
    : username_(params.user.username),
      session_id_(params.request.session_id),
      fake_client_ipv4_(std::move(fake_client_ipv4)),
      fake_client_ipv6_(std::move(fake_client_ipv6)),
      shaper_to_websocket_(params.user.bandwidth_bites_seconds),
      shaper_from_websocket_(params.user.bandwidth_bites_seconds) {
  connection_params_.insert(
      {params.client_id, ClientConnection::Create(params)});
}

bool ConnectionMultiplexer::AddClientConnection(const ConnectParams& params) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (connection_params_.contains(params.client_id)) {
    return false;
  }
  auto client_connection = ClientConnection::Create(params);
  connection_params_.insert({params.client_id, std::move(client_connection)});
  return true;
}

common::network::IPPacketPtr ConnectionMultiplexer::PacketPreparingToWebsocket(
    common::network::IPPacketPtr packet) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  if (connection_params_.empty()) {
    return nullptr;
  }

  if (!shaper_to_websocket_.CanProcessPacket(packet->Size())) {
    return nullptr;
  }

#ifdef FPTN_IP_ADDRESS_WITHOUT_PCAP
  if (packet->IsIPv4()) {
    packet->SetSrcIPv4Address(fake_client_ipv4_.ToString());
  } else if (packet->IsIPv6()) {
    packet->SetSrcIPv6Address(fake_client_ipv6_.ToString());
  } else {
    return nullptr;
  }
#else
  if (packet->IsIPv4()) {
    packet->SetSrcIPv4Address(fake_client_ipv4_.Get());
  } else if (packet->IsIPv6()) {
    packet->SetSrcIPv6Address(fake_client_ipv6_.Get());
  } else {
    return nullptr;
  }
#endif
  packet->ComputeCalculateFields();
  return packet;
}

common::network::IPPacketPtr
ConnectionMultiplexer::PacketPreparingFromWebsocket(
    common::network::IPPacketPtr packet) {
  if (!shaper_from_websocket_.CanProcessPacket(packet->Size())) {
    return nullptr;
  }

  const auto& connection = connection_params_.begin()->second;
#ifdef FPTN_IP_ADDRESS_WITHOUT_PCAP
  if (packet->IsIPv4()) {
    packet->SetDstIPv4Address(
        connection->Params().request.client_tun_vpn_ipv4.ToString());
  } else if (packet->IsIPv6()) {
    packet->SetDstIPv6Address(
        connection->Params().request.client_tun_vpn_ipv6.ToString());
  }
#else
  if (packet->IsIPv4()) {
    packet->SetDstIPv4Address(
        connection->Params().request.client_tun_vpn_ipv4.Get());
  } else if (packet->IsIPv6()) {
    packet->SetDstIPv6Address(
        connection->Params().request.client_tun_vpn_ipv6.Get());
  }
#endif
  packet->ComputeCalculateFields();
  return packet;
}

bool ConnectionMultiplexer::HasClientId(fptn::ClientID client_id) const {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return connection_params_.contains(client_id);
}

bool ConnectionMultiplexer::DelConnectionByClientId(fptn::ClientID client_id) {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return connection_params_.erase(client_id) > 0;
}

const std::string& ConnectionMultiplexer::Username() const { return username_; }

std::size_t ConnectionMultiplexer::Size() const {
  const std::unique_lock<std::mutex> lock(mutex_);  // mutex

  return connection_params_.size();
}

const std::string& ConnectionMultiplexer::SessionId() const {
  return session_id_;
}

const IPv4Address& ConnectionMultiplexer::FakeClientIPv4() const noexcept {
  return fake_client_ipv4_;
}

const IPv6Address& ConnectionMultiplexer::FakeClientIPv6() const noexcept {
  return fake_client_ipv6_;
}

}  // namespace fptn::nat
