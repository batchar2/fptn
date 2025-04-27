/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <ctime>
#include <random>
#include <stdexcept>
#include <string>

#include "common/network/ip_packet.h"
#include "common/utils/utils.h"

namespace fptn::protocol::protobuf {
class ProcessingError : public std::runtime_error {
 public:
  explicit ProcessingError(const std::string& message)
      : std::runtime_error(message) {}
};

class MessageError : public std::runtime_error {
 public:
  explicit MessageError(const std::string& message)
      : std::runtime_error(message) {}
};

class UnsupportedProtocolVersion : public std::runtime_error {
 public:
  explicit UnsupportedProtocolVersion(const std::string& message)
      : std::runtime_error(message) {}
};

std::string GetProtoPayload(const std::string& raw);
std::string CreateProtoPayload(fptn::common::network::IPPacketPtr packet);
}  // namespace fptn::protocol::protobuf
