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
 *  - SendBatchImpl()      - Packet transmission
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
    std::uint32_t ipv4_netmask = 32;
    fptn::common::network::IPv6Address ipv6_addr;
    std::uint32_t ipv6_netmask = 126;
  };

  bool Start(Config config) {
    runtime_config_ = std::move(config);
    return impl()->StartImpl();
  }

  bool Stop() { return impl()->StopImpl(); }

  bool Send(IPPacketPtr packet) { return impl()->SendImpl(std::move(packet)); }

  bool SendBatch(std::vector<IPPacketPtr> packets) {
    return impl()->SendBatchImpl(std::move(packets));
  }

  std::size_t GetSendRate() { return impl()->GetSendRateImpl(); }

  std::size_t GetReceiveRate() { return impl()->GetReceiveRateImpl(); }

  void SetName(const std::string& name) { name_ = name; }

 private:
  explicit BaseNetInterface(
      std::string name, int mtu_size, bool using_rate_calculator)
      : name_(std::move(name)),
        mtu_size_(mtu_size),
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

  [[nodiscard]] int MtuSize() const noexcept { return mtu_size_; }

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
  int mtu_size_;

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
      std::string name, int mtu_size, bool using_rate_calculator = true)
      : Base(std::move(name), mtu_size, using_rate_calculator),
        running_(false) {}

  ~GenericTunInterface() { StopImpl(); }

 protected:
  bool StartImpl() noexcept {
    const std::scoped_lock lock(mutex_);  // mutex

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
      device_.SetNonBlocking(true);
      device_.SetMTU(this->MtuSize());
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
    {
      const std::scoped_lock lock(mutex_);  // mutex

      // cppcheck-suppress identicalConditionAfterEarlyExit
      if (!running_) {  // Double-check after acquiring lock
        return false;
      }
      running_ = false;
    }

    if (thread_.joinable()) {
      thread_.join();
    }

    device_.Close();

    return true;
  }

  bool SendImpl(IPPacketPtr packet) noexcept {
    try {
      static const bool kRateCalculator = this->UsingRateCalculator();

      if (running_ && packet) {
        const auto* raw_packet = packet->GetRawPacket();
        if (raw_packet) {
          const auto* data = raw_packet->getRawData();
          const auto len = raw_packet->getRawDataLen();

          if (data && len > 0) {
            const std::scoped_lock lock(mutex_);  // mutex

            const int bytes_written =
                device_.Write(data, static_cast<int>(len));
            if (kRateCalculator && bytes_written > 0) {
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

  bool SendBatchImpl(std::vector<IPPacketPtr> packets) noexcept {
    try {
      static const bool kRateCalculator = this->UsingRateCalculator();

      if (!running_ || packets.empty()) {
        return false;
      }

      // serialize
      std::vector<IPPacketData> serialized_packets;
      serialized_packets.reserve(packets.size());
      std::size_t total_bytes = 0;
      for (auto& packet : packets) {
        if (packet && packet->Size()) {
          const auto* raw_packet = packet->GetRawPacket();
          if (raw_packet) {
            const auto* data = raw_packet->getRawData();
            const auto len = raw_packet->getRawDataLen();
            if (data && len > 0) {
              serialized_packets.emplace_back(data, data + len);
              total_bytes += len;
            }
          }
        }
      }

      // send
      if (!serialized_packets.empty()) {
        const std::scoped_lock lock(mutex_);  // mutex

        for (const auto& packet_data : serialized_packets) {
          const int bytes_written = device_.Write(
              packet_data.data(), static_cast<int>(packet_data.size()));
          if (bytes_written != static_cast<int>(packet_data.size())) {
            return false;
          }
        }
      }

      if (kRateCalculator && total_bytes) {
        send_rate_calculator_.Update(total_bytes);
      }

      return true;
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
    const int mtu_size = this->MtuSize();
    const auto callback = this->GetRecvIPPacketCallback();
    const bool rate_calc = this->UsingRateCalculator();

    constexpr int kBatchIPPacketsSize = 16;
    std::vector<IPPacketPtr> batch_ip_packets;
    batch_ip_packets.reserve(kBatchIPPacketsSize);

    while (running_) {
      std::size_t total_bytes = 0;

      // collect batch
      for (int i = 0; i < kBatchIPPacketsSize && running_; ++i) {
        std::vector<std::uint8_t> buffer(mtu_size);
        const int size = device_.Read(buffer.data(), mtu_size);
        if (size > 0) {
          buffer.resize(size);
          auto packet = IPPacket::Parse(std::move(buffer));
          if (packet) {
            total_bytes += packet->Size();
            batch_ip_packets.emplace_back(std::move(packet));
          }
        } else {
          break;
        }
      }

      // send batch
      if (!batch_ip_packets.empty() && running_) {
        if (rate_calc) {
          receive_rate_calculator_.Update(total_bytes);
        }
        for (auto& packet : batch_ip_packets) {
          callback(std::move(packet));
        }
        batch_ip_packets.clear();
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

 private:
  mutable std::mutex mutex_;

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
