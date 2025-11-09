/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "client/session.h"

#include <string>
#include <utility>

using fptn::client::Session;
using fptn::common::network::IPv4Address;
using fptn::common::network::IPv6Address;

Session::Session(ClientID client_id,
    std::string user_name,
    IPv4Address client_ipv4,
    IPv4Address fake_client_ipv4,
    IPv6Address client_ipv6,
    IPv6Address fake_client_ipv6,
    fptn::traffic_shaper::LeakyBucketSPtr to_client,
    fptn::traffic_shaper::LeakyBucketSPtr from_client)
    : client_id_(client_id),
      user_name_(std::move(user_name)),
      client_ipv4_(std::move(client_ipv4)),
      fake_client_ipv4_(std::move(fake_client_ipv4)),
      client_ipv6_(std::move(client_ipv6)),
      fake_client_ipv6_(std::move(fake_client_ipv6)),
      to_client_(std::move(to_client)),
      from_client_(std::move(from_client)) {}

const fptn::ClientID& Session::ClientId() const noexcept { return client_id_; }

const std::string& Session::UserName() const noexcept { return user_name_; }

const IPv4Address& Session::ClientIPv4() const noexcept { return client_ipv4_; }

const IPv4Address& Session::FakeClientIPv4() const noexcept {
  return fake_client_ipv4_;
}

const IPv6Address& Session::ClientIPv6() const noexcept { return client_ipv6_; }

const IPv6Address& Session::FakeClientIPv6() const noexcept {
  return fake_client_ipv6_;
}

fptn::traffic_shaper::LeakyBucketSPtr&
Session::TrafficShaperToClient() noexcept {
  return to_client_;
}

fptn::traffic_shaper::LeakyBucketSPtr&
Session::TrafficShaperFromClient() noexcept {
  return from_client_;
}

fptn::common::network::IPPacketPtr Session::ChangeIPAddressToClientIP(
    fptn::common::network::IPPacketPtr packet) noexcept {
  packet->SetClientId(client_id_);

#ifdef FPTN_IP_ADDRESS_WITHOUT_PCAP
  if (packet->IsIPv4()) {
    packet->SetDstIPv4Address(client_ipv4_.ToString());
  } else if (packet->IsIPv6()) {
    packet->SetDstIPv6Address(client_ipv6_.ToString());
  }
#else
  if (packet->IsIPv4()) {
    packet->SetDstIPv4Address(client_ipv4_.Get());
  } else if (packet->IsIPv6()) {
    packet->SetDstIPv6Address(client_ipv6_.Get());
  }
#endif
  packet->ComputeCalculateFields();
  return packet;
}

fptn::common::network::IPPacketPtr Session::ChangeIPAddressToFakeIP(
    fptn::common::network::IPPacketPtr packet) noexcept {
  packet->SetClientId(client_id_);
#ifdef FPTN_IP_ADDRESS_WITHOUT_PCAP
  if (packet->IsIPv4()) {
    packet->SetSrcIPv4Address(fake_client_ipv4_.ToString());
  } else if (packet->IsIPv6()) {
    packet->SetSrcIPv6Address(fake_client_ipv6_.ToString());
  }
#else
  if (packet->IsIPv4()) {
    packet->SetSrcIPv4Address(fake_client_ipv4_.Get());
  } else if (packet->IsIPv6()) {
    packet->SetSrcIPv6Address(fake_client_ipv6_.Get());
  }
#endif
  packet->ComputeCalculateFields();
  return packet;
}
