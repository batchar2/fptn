/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "vpn/vpn_client.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>

using fptn::vpn::VpnClient;

VpnClient::VpnClient(fptn::http::ClientPtr http_client,
    fptn::common::network::BaseNetInterfacePtr virtual_net_interface,
    const pcpp::IPv4Address& dns_server_ipv4,
    const pcpp::IPv6Address& dns_server_ipv6)
    : http_client_(std::move(http_client)),
      virtual_net_interface_(std::move(virtual_net_interface)),
      dns_server_ipv4_(dns_server_ipv4),
      dns_server_ipv6_(dns_server_ipv6) {}

VpnClient::~VpnClient() { Stop(); }

bool VpnClient::IsStarted() {
  return http_client_ && http_client_->IsStarted();
}

void VpnClient::Start() {
  // NOLINTNEXTLINE(modernize-avoid-bind)
  http_client_->SetNewIPPacketCallback(std::bind(
      &VpnClient::HandlePacketFromWebSocket, this, std::placeholders::_1));

  virtual_net_interface_->SetNewIPPacketCallback(
      // NOLINTNEXTLINE(modernize-avoid-bind)
      std::bind(&VpnClient::HandlePacketFromVirtualNetworkInterface, this,
          std::placeholders::_1));

  http_client_->Start();
  virtual_net_interface_->Start();
}

void VpnClient::Stop() {
  if (http_client_) {
    http_client_->Stop();
    http_client_.reset();
  }
  if (virtual_net_interface_) {
    virtual_net_interface_->Stop();
    virtual_net_interface_.reset();
  }
}

std::size_t VpnClient::GetSendRate() {
  return virtual_net_interface_->GetSendRate();
}

std::size_t VpnClient::GetReceiveRate() {
  return virtual_net_interface_->GetReceiveRate();
}

void VpnClient::HandlePacketFromVirtualNetworkInterface(
    fptn::common::network::IPPacketPtr packet) {
  http_client_->Send(std::move(packet));
}

void VpnClient::HandlePacketFromWebSocket(
    fptn::common::network::IPPacketPtr packet) {
  virtual_net_interface_->Send(std::move(packet));
}
