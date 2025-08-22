/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <string>
#include <utility>

#ifdef FPTN_IP_ADDRESS_WITHOUT_PCAP
#else
#include <pcapplusplus/IpAddress.h>
#endif

namespace fptn::common::network {

#ifdef FPTN_IP_ADDRESS_WITHOUT_PCAP

#else

template <class T>
class IPAddress {
 public:
  // Default constructor
  IPAddress() = default;

  explicit IPAddress(const std::string& ip) : ip_(ip), ip_impl_(ip) {}

  T Get() const noexcept { return ip_impl_; }

  bool IsEmpty() const { return ip_.empty() || ip_impl_ == T(); }

  const std::string& ToString() const { return ip_; }

  // Add copy and move constructors/assignment for base class
  IPAddress(const IPAddress& other)
      : ip_(other.ip_), ip_impl_(other.ip_impl_) {}
  IPAddress(IPAddress&& other) noexcept
      : ip_(std::move(other.ip_)), ip_impl_(std::move(other.ip_impl_)) {}

  IPAddress& operator=(const IPAddress& other) {
    if (this != &other) {
      ip_ = other.ip_;
      ip_impl_ = other.ip_impl_;
    }
    return *this;
  }

  IPAddress& operator=(IPAddress&& other) noexcept {
    if (this != &other) {
      ip_ = std::move(other.ip_);
      ip_impl_ = std::move(other.ip_impl_);
    }
    return *this;
  }
  bool operator!=(const IPAddress<T>& other) const noexcept {
    return ip_ != other.ip_ || ip_impl_ != other.ip_impl_;
  }

  bool operator==(const IPAddress<T>& other) const noexcept {
    return ip_ == other.ip_ && ip_impl_ == other.ip_impl_;
  }

  std::uint32_t ToInt() const { return ip_impl_.toInt(); }

 private:
  std::string ip_;
  T ip_impl_;
};

class IPv4Address : public IPAddress<pcpp::IPv4Address> {
 public:
  // Default constructor - explicitly calls base class default constructor
  IPv4Address() = default;

  // Constructor from string - explicitly calls base class constructor
  explicit IPv4Address(std::string ip)
      : IPAddress<pcpp::IPv4Address>(std::move(ip)) {}

  // Constructor from pcpp::IPv4Address object - explicitly calls base class
  // constructor
  explicit IPv4Address(const pcpp::IPv4Address& ip_addr)
      : IPAddress<pcpp::IPv4Address>(ip_addr.toString()) {}

  // Copy constructor - explicitly calls base class copy constructor
  IPv4Address(const IPv4Address& other) : IPAddress<pcpp::IPv4Address>(other) {}

  // Move constructor - explicitly calls base class move constructor
  IPv4Address(IPv4Address&& other) noexcept
      : IPAddress<pcpp::IPv4Address>(std::move(other)) {}

  // Copy assignment operator
  IPv4Address& operator=(const IPv4Address& other) {
    if (this != &other) {
      IPAddress<pcpp::IPv4Address>::operator=(other);
    }
    return *this;
  }

  // Move assignment operator
  IPv4Address& operator=(IPv4Address&& other) noexcept {
    if (this != &other) {
      IPAddress<pcpp::IPv4Address>::operator=(std::move(other));
    }
    return *this;
  }

  static IPv4Address Create(std::string ip) {
    return IPv4Address(std::move(ip));
  }

  static IPv4Address Create(const pcpp::IPv4Address& ip_addr) {
    return IPv4Address(ip_addr);
  }

  static IPv4Address Create(const IPv4Address& ip_addr) {
    return IPv4Address(ip_addr);
  }
};

class IPv6Address : public IPAddress<pcpp::IPv6Address> {
 public:
  // Default constructor - explicitly calls base class default constructor
  IPv6Address() = default;

  // Constructor from string - explicitly calls base class constructor
  explicit IPv6Address(std::string ip)
      : IPAddress<pcpp::IPv6Address>(std::move(ip)) {}

  // Constructor from pcpp::IPv6Address object - explicitly calls base class
  // constructor
  explicit IPv6Address(const pcpp::IPv6Address& ip_addr)
      : IPAddress<pcpp::IPv6Address>(ip_addr.toString()) {}

  // Copy constructor - explicitly calls base class copy constructor
  IPv6Address(const IPv6Address& other) : IPAddress<pcpp::IPv6Address>(other) {}

  // Move constructor - explicitly calls base class move constructor
  IPv6Address(IPv6Address&& other) noexcept
      : IPAddress<pcpp::IPv6Address>(std::move(other)) {}

  // Copy assignment operator
  IPv6Address& operator=(const IPv6Address& other) {
    if (this != &other) {
      IPAddress<pcpp::IPv6Address>::operator=(other);
    }
    return *this;
  }

  // Move assignment operator
  IPv6Address& operator=(IPv6Address&& other) noexcept {
    if (this != &other) {
      IPAddress<pcpp::IPv6Address>::operator=(std::move(other));
    }
    return *this;
  }

  static IPv6Address Create(std::string ip) {
    return IPv6Address(std::move(ip));
  }

  static IPv6Address Create(const pcpp::IPv6Address& ip_addr) {
    return IPv6Address(ip_addr);
  }

  static IPv6Address Create(const IPv6Address& ip_addr) {
    return IPv6Address(ip_addr);
  }
};

#endif

}  // namespace fptn::common::network
