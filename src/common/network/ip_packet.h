/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#if _WIN32
#pragma warning(disable : 4996)
#endif

#if _WIN32
#include <Winsock2.h>  // NOLINT(build/include_order)

#include <openssl/base.h>  // NOLINT(build/include_order)
#else
#include <arpa/inet.h>
#endif

#include <iostream>

#include <pcapplusplus/ArpLayer.h>     // NOLINT(build/include_order)
#include <pcapplusplus/EthLayer.h>     // NOLINT(build/include_order)
#include <pcapplusplus/IPv4Layer.h>    // NOLINT(build/include_order)
#include <pcapplusplus/IPv6Layer.h>    // NOLINT(build/include_order)
#include <pcapplusplus/IcmpV6Layer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/MacAddress.h>   // NOLINT(build/include_order)
#include <pcapplusplus/Packet.h>       // NOLINT(build/include_order)
#include <spdlog/spdlog.h>             // NOLINT(build/include_order)

#ifdef TCPOPT_CC
#undef TCPOPT_CC
#endif  // TCPOPT_CC
#ifdef TCPOPT_CCNEW
#undef TCPOPT_CCNEW
#endif  // TCPOPT_CCNEW
#ifdef TCPOPT_CCECHO
#undef TCPOPT_CCECHO
#endif  // TCPOPT_CCECHO

#include <pcapplusplus/TcpLayer.h>  // NOLINT(build/include_order)
#include <pcapplusplus/UdpLayer.h>  // NOLINT(build/include_order)

#include "common/client_id.h"

#if _WIN32
#pragma warning(default : 4996)
#endif

namespace fptn::common::network {

#define FPTN_PACKET_UNDEFINED_CLIENT_ID MAX_CLIENT_ID

#ifndef __ANDROID__

inline bool CheckIPv4(const std::string& buffer) {
  return (static_cast<uint8_t>(buffer[0]) >> 4) == 4;
}

inline bool CheckIPv6(const std::string& buffer) {
  return (static_cast<uint8_t>(buffer[0]) >> 4) == 6;
}

class IPPacket {
 public:
  static std::unique_ptr<IPPacket> Parse(std::string buffer,
      fptn::ClientID client_id = FPTN_PACKET_UNDEFINED_CLIENT_ID) {
    if (buffer.empty() || buffer.size() < 20) {  // Minimum IPv4 header size
      return nullptr;
    }
    if (CheckIPv4(buffer)) {
      auto packet = std::make_unique<IPPacket>(
          std::move(buffer), client_id, pcpp::LINKTYPE_IPV4);
      if (nullptr != packet->IPv4Layer()) {
        return packet;
      }
    } else if (CheckIPv6(buffer)) {
      auto packet = std::make_unique<IPPacket>(
          std::move(buffer), client_id, pcpp::LINKTYPE_IPV6);
      if (nullptr != packet->IPv6Layer()) {
        return packet;
      }
    }
    return nullptr;
  }

  static std::unique_ptr<IPPacket> Parse(const std::uint8_t* data,
      const std::size_t size,
      fptn::ClientID client_id = FPTN_PACKET_UNDEFINED_CLIENT_ID) {
    std::string buffer(reinterpret_cast<const char*>(data), size);
    return Parse(std::move(buffer), client_id);
  }

 public:
  IPPacket(
      std::string data, fptn::ClientID client_id, pcpp::LinkLayerType ip_type)
      : packet_data_(std::move(data)), client_id_(client_id) {
    try {
      raw_packet_ = pcpp::RawPacket(
          reinterpret_cast<const uint8_t*>(packet_data_.data()),
          static_cast<int>(packet_data_.size()), timeval{0, 0}, false, ip_type);

      parsed_packet_ = pcpp::Packet(&raw_packet_, false);
      if (pcpp::LINKTYPE_IPV4 == ip_type) {
        ipv4_layer_ = parsed_packet_.getLayerOfType<pcpp::IPv4Layer>();
      } else if (pcpp::LINKTYPE_IPV6 == ip_type) {
        ipv6_layer_ = parsed_packet_.getLayerOfType<pcpp::IPv6Layer>();
      }
    } catch (const std::exception& e) {
      SPDLOG_WARN(
          "IP Packet parsing exception (client {}): {}", client_id_, e.what());
    } catch (...) {
      SPDLOG_WARN("Unknown error while parsing IP Packet");
    }
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  void ComputeCalculateFields() noexcept {
    auto* tcp_layer = parsed_packet_.getLayerOfType<pcpp::TcpLayer>();
    if (tcp_layer) {
      tcp_layer->computeCalculateFields();
    } else {
      auto* udp_layer = parsed_packet_.getLayerOfType<pcpp::UdpLayer>();
      if (udp_layer) {
        udp_layer->computeCalculateFields();
      }
    }
    if (ipv4_layer_) {
      ipv4_layer_->computeCalculateFields();
    } else if (ipv6_layer_) {
      auto* icmp_layer = parsed_packet_.getLayerOfType<pcpp::IcmpV6Layer>();
      if (icmp_layer) {
        icmp_layer->computeCalculateFields();
      }
      ipv6_layer_->computeCalculateFields();
    }
  }

  void SetClientId(fptn::ClientID client_id) noexcept {
    client_id_ = client_id;
  }

  void SetDstIPv4Address(const pcpp::IPv4Address& dst) noexcept {
    if (ipv4_layer_) {
      ipv4_layer_->getIPv4Header()->timeToLive -= 1;
      ipv4_layer_->setDstIPv4Address(dst);
    }
  }

  void SetSrcIPv4Address(const pcpp::IPv4Address& src) noexcept {
    if (ipv4_layer_) {
      ipv4_layer_->getIPv4Header()->timeToLive -= 1;
      ipv4_layer_->setSrcIPv4Address(src);
    }
  }

  void SetDstIPv6Address(const pcpp::IPv6Address& dst) noexcept {
    if (ipv6_layer_) {
      ipv6_layer_->setDstIPv6Address(dst);
    }
  }

  void SetSrcIPv6Address(const pcpp::IPv6Address& src) noexcept {
    if (ipv6_layer_) {
      ipv6_layer_->setSrcIPv6Address(src);
    }
  }

  fptn::ClientID ClientId() const noexcept { return client_id_; }

  pcpp::Packet& Pkt() noexcept { return parsed_packet_; }

  std::size_t Size() const noexcept { return packet_data_.size(); }

  const pcpp::RawPacket* GetRawPacket() const noexcept {
    return parsed_packet_.getRawPacket();
  }

 public:
  // TODO(stas): Remove virtual functions in the future for better performance.
  // TODO(stas): Anti-scan tests are currently inadequate and need improvement.
  virtual ~IPPacket() = default;
  virtual bool IsIPv4() const noexcept { return ipv4_layer_ != nullptr; }
  virtual bool IsIPv6() const noexcept { return ipv6_layer_ != nullptr; }
  virtual pcpp::IPv4Layer* IPv4Layer() noexcept { return ipv4_layer_; }
  virtual pcpp::IPv6Layer* IPv6Layer() noexcept { return ipv6_layer_; }

 protected:
  // for tests only
  IPPacket() : client_id_(FPTN_PACKET_UNDEFINED_CLIENT_ID) {}

 private:
  std::string packet_data_;
  fptn::ClientID client_id_;
  pcpp::RawPacket raw_packet_;
  pcpp::Packet parsed_packet_;

  pcpp::IPv4Layer* ipv4_layer_ = nullptr;
  pcpp::IPv6Layer* ipv6_layer_ = nullptr;
};

using IPPacketPtr = std::unique_ptr<IPPacket>;

#else

/**
 * Android-specific lightweight container for IPv4 packets.
 * Wraps raw IP packet data with basic access methods.
 */
class LightIPv4Packet {
 public:
  static std::unique_ptr<LightIPv4Packet> Parse(std::string buffer,
      std::uint64_t client_id = FPTN_PACKET_UNDEFINED_CLIENT_ID) {
    if (buffer.empty() || buffer.size() < 20) {  // Minimum IPv4 header size
      return nullptr;
    }
    return std::make_unique<LightIPv4Packet>(std::move(buffer), client_id);
  }

  static std::unique_ptr<LightIPv4Packet> Parse(const std::uint8_t* data,
      const std::size_t size,
      const fptn::ClientID client_id = FPTN_PACKET_UNDEFINED_CLIENT_ID) {
    std::string buffer(reinterpret_cast<const char*>(data), size);
    return Parse(std::move(buffer), client_id);
  }

  LightIPv4Packet(std::string buffer, const fptn::ClientID client_id)
      : ip_packet_(std::move(buffer)) {
    (void)client_id;
  }

  std::size_t Size() const { return ip_packet_.size(); }

  // specific methods to have general interface with IPPacket
  const LightIPv4Packet* GetRawPacket() const { return this; }
  std::size_t getRawDataLen() const { return ip_packet_.size(); }
  const void* getRawData() const { return ip_packet_.data(); }

 private:
  const std::string ip_packet_;
};

using IPPacket = LightIPv4Packet;
using IPPacketPtr = std::unique_ptr<LightIPv4Packet>;

#endif

}  // namespace fptn::common::network
