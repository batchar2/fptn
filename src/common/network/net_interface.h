/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov
Copyright (c) 2024-2026 Pavel Shpilev

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include "common/data/channel.h"
#include "common/network/data_rate_calculator.h"
#include "common/network/ip_address.h"
#include "common/network/ip_packet.h"

namespace fptn::common::network {

using NewIPPacketCallback = std::function<void(IPPacketPtr packet)>;

/**
 * @brief Base network interface class using CRTP (Curiously Recurring Template
 * Pattern)
 *
 * This template provides common interface functionality while delegating
 * platform-specific operations to the derived implementation class.
 *
 * CRTP Benefits:
 *  - Static polymorphism (no virtual function overhead)
 *  - Clear separation of interface and implementation
 *  - Compile-time enforcement of interface contracts
 *
 * Derived classes must implement:
 *  - StartImpl()     - Initialize the interface
 *  - StopImpl()      - Shutdown the interface
 *  - SendImpl()      - Packet transmission
 *  - GetSendRateImpl()    - Outbound rate monitoring
 *  - GetReceiveRateImpl() - Inbound rate monitoring
 */
template <typename Implementation>
class BaseNetInterface {
 public:
  friend Implementation;

  // Network configuration
  struct Config {
    fptn::common::network::IPv4Address ipv4_addr;
    int ipv4_netmask = 32;
    fptn::common::network::IPv6Address ipv6_addr;
    int ipv6_netmask = 126;
  };

  bool Start(Config config) {
    runtime_config_ = std::move(config);
    return impl()->StartImpl();
  }

  bool Stop() { return impl()->StopImpl(); }

  bool Send(IPPacketPtr packet) { return impl()->SendImpl(std::move(packet)); }

  std::size_t GetSendRate() { return impl()->GetSendRateImpl(); }

  std::size_t GetReceiveRate() { return impl()->GetReceiveRateImpl(); }

  void SetName(const std::string& name) { name_ = name; }

 private:
  explicit BaseNetInterface(std::string name, bool using_rate_calculator)
      : name_(std::move(name)),
        recv_ip_packet_callback_(nullptr),
        runtime_config_(),
        using_rate_calculator_(using_rate_calculator) {}

  Implementation* impl() { return static_cast<Implementation*>(this); }

 public:
  [[nodiscard]] const std::string& Name() const noexcept { return name_; }

  [[nodiscard]] const fptn::common::network::IPv4Address& IPv4Addr()
      const noexcept {
    return runtime_config_.ipv4_addr;
  }

  [[nodiscard]] int IPv4Netmask() const noexcept {
    return runtime_config_.ipv4_netmask;
  }

  [[nodiscard]] const fptn::common::network::IPv6Address& IPv6Addr()
      const noexcept {
    return runtime_config_.ipv6_addr;
  }

  bool UsingRateCalculator() const noexcept { return using_rate_calculator_; }

  int IPv6Netmask() const noexcept { return runtime_config_.ipv6_netmask; }

  void SetRecvIPPacketCallback(const NewIPPacketCallback& callback) noexcept {
    recv_ip_packet_callback_ = callback;
  }

  [[nodiscard]] NewIPPacketCallback GetRecvIPPacketCallback() const {
    return recv_ip_packet_callback_;
  }

 private:
  std::string name_;
  NewIPPacketCallback recv_ip_packet_callback_;

  Config runtime_config_;

  const bool using_rate_calculator_;
};

/**
 * @brief Generic TUN interface parameterized by a platform-specific Device.
 *
 * The Device type must satisfy the following concept (duck-typed):
 *   bool Open(const std::string& name);
 *   void Close();
 *   std::string GetName() const;
 *   bool ConfigureIPv4(const std::string& addr, int mask);
 *   bool ConfigureIPv6(const std::string& addr, int mask);
 *   void SetNonBlocking(bool enabled);
 *   void SetMTU(int mtu);
 *   void BringUp();
 *   int  Read(void* buffer, int size);
 *   int  Write(const void* data, int size);
 *   void SetStopFlag(const std::atomic<bool>* running);
 *
 * Platform-specific devices: LinuxTunDevice, DarwinTunDevice, WinTunDevice
 */
template <typename Device>
class GenericTunInterface final
    : public BaseNetInterface<GenericTunInterface<Device>> {
 public:
  using Base = BaseNetInterface<GenericTunInterface<Device>>;
  friend Base;

  using Config = typename Base::Config;

  explicit GenericTunInterface(
      std::string name, bool using_rate_calculator = true)
      : Base(std::move(name), using_rate_calculator),
        mtu_(FPTN_MTU_SIZE),
        running_(false) {}

  ~GenericTunInterface() { StopImpl(); }

 protected:
  bool StartImpl() noexcept {
    const std::scoped_lock lock(mutex_);

    try {
      // cppcheck-suppress knownConditionTrueFalse
      if (!device_.Open(this->Name())) {
        SPDLOG_ERROR("Failed to open TUN device");
        return false;
      }
      // Update name to actual device name (may differ, e.g., utun on macOS)
      this->SetName(device_.GetName());

      /* set IPv6 */
      // cppcheck-suppress knownConditionTrueFalse
      if (!device_.ConfigureIPv6(
              this->IPv6Addr().ToString(), this->IPv6Netmask())) {
        SPDLOG_WARN("IPv6 configuration failed, continuing with IPv4 only");
      }
      /* set IPv4 */
      // cppcheck-suppress knownConditionTrueFalse
      if (!device_.ConfigureIPv4(
              this->IPv4Addr().ToString(), this->IPv4Netmask())) {
        SPDLOG_ERROR("IPv4 configuration failed");
        device_.Close();
        return false;
      }
      device_.SetNonBlocking(false);
      device_.SetMTU(mtu_);
      device_.BringUp();

      running_ = true;
      device_.SetStopFlag(&running_);
      thread_ = std::thread(&GenericTunInterface::Run, this);
      return thread_.joinable();
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("Error start: {}", ex.what());
    }
    return false;
  }

  bool StopImpl() noexcept {
    if (!running_) {
      return false;
    }

    const std::scoped_lock lock(mutex_);

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (!running_) {  // Double-check after acquiring lock
      return false;
    }

    device_.Close();

    if (thread_.joinable()) {
      running_ = false;
      thread_.join();
    }
    return true;
  }

  bool SendImpl(IPPacketPtr packet) noexcept {
    try {
      if (running_ && packet && packet->Size()) {
        const auto* raw_packet = packet->GetRawPacket();
        if (raw_packet) {
          const auto* data = raw_packet->getRawData();
          const auto len = raw_packet->getRawDataLen();

          if (data && len > 0) {
            const std::scoped_lock lock(mutex_);  // mutex

            const int bytes_written =
                device_.Write(data, static_cast<int>(len));
            if (this->UsingRateCalculator() && bytes_written > 0) {
              send_rate_calculator_.Update(bytes_written);
            }

            return bytes_written == len;
          }
        }
      }
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("SendImpl error: {}", ex.what());
    }
    return false;
  }

  std::size_t GetSendRateImpl() const noexcept {
    return send_rate_calculator_.GetRateForSecond();
  }

  std::size_t GetReceiveRateImpl() const noexcept {
    return receive_rate_calculator_.GetRateForSecond();
  }

  void Run() {
    const auto callback = this->GetRecvIPPacketCallback();
    while (running_) {
      std::vector<std::uint8_t> buffer(mtu_);
      const int size = device_.Read(buffer.data(), mtu_);
      if (size > 0 && running_) {
        buffer.resize(size);
        auto packet = IPPacket::Parse(buffer);
        if (running_ && packet != nullptr && callback) {
          if (this->UsingRateCalculator()) {
            receive_rate_calculator_.Update(packet->Size());  // calculate rate
          }
          callback(std::move(packet));
        }
      }
    }
  }

 private:
  mutable std::mutex mutex_;

  const std::uint16_t mtu_;

  std::atomic<bool> running_;
  std::thread thread_;
  Device device_;
  DataRateCalculator send_rate_calculator_;
  DataRateCalculator receive_rate_calculator_;
};

}  // namespace fptn::common::network

// Platform-specific TUN device includes (outside namespace to avoid nesting)
#if defined(__APPLE__)
#include "common/network/tun/darwin_tun_device.h"
#elif defined(__linux__)
#include "common/network/tun/linux_tun_device.h"
#elif defined(_WIN32)
#include "common/network/tun/win_tun_device.h"
#endif

namespace fptn::common::network {
// Platform-specific TUN interface aliases
#if defined(__APPLE__)
using TunInterface = GenericTunInterface<DarwinTunDevice>;
#elif defined(__linux__)
using TunInterface = GenericTunInterface<LinuxTunDevice>;
#elif defined(_WIN32)
using TunInterface = GenericTunInterface<WinTunDevice>;
#endif

using TunInterfaceSPtr = std::shared_ptr<TunInterface>;
}  // namespace fptn::common::network
