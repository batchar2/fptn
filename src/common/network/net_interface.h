/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

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

#if defined(__APPLE__) || defined(__linux__)
#include <tuntap++.hh>  // NOLINT(build/include_order)
#elif _WIN32
// clang-format off
#include <Ws2tcpip.h>  // NOLINT(build/include_order)
#include <windows.h>   // NOLINT(build/include_order)
#include <objbase.h>   // NOLINT(build/include_order)
#include <winsock2.h>  // NOLINT(build/include_order)
#include <Iprtrmib.h>  // NOLINT(build/include_order)
#include <iphlpapi.h>  // NOLINT(build/include_order)
#include <WinError.h>  // NOLINT(build/include_order)
#include <wintun.h>    // NOLINT(build/include_order)
// clang-format on
#endif

#include "common/network/ip_packet.h"

namespace fptn::common::network {
class DataRateCalculator {
 public:
  explicit DataRateCalculator(
      std::chrono::milliseconds interval = std::chrono::milliseconds(1000))
      : interval_(interval),
        bytes_(0),
        lastUpdateTime_(std::chrono::steady_clock::now()),
        rate_(0) {}
  void Update(std::size_t len) noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = now - lastUpdateTime_;
    bytes_ += len;
    if (elapsed >= interval_) {
      rate_ = static_cast<std::size_t>(bytes_ / elapsed.count());
      lastUpdateTime_ = now;
      bytes_ = 0;
    }
  }
  std::size_t GetRateForSecond() const noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    const auto interval_count = interval_.count();
    if (interval_count) {
      return static_cast<std::size_t>(rate_ / (1000 / interval_.count()));
    }
    return 0;
  }

 private:
  mutable std::mutex mutex_;
  std::chrono::milliseconds interval_;
  std::atomic<std::size_t> bytes_;
  std::chrono::steady_clock::time_point lastUpdateTime_;
  std::atomic<std::size_t> rate_;
};

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
    std::string name;
    pcpp::IPv4Address ipv4_addr;
    int ipv4_netmask;
    pcpp::IPv6Address ipv6_addr;
    int ipv6_netmask;
  };

  bool Start() { return impl()->StartImpl(); }

  bool Stop() { return impl()->StopImpl(); }

  bool Send(IPPacketPtr packet) { return impl()->SendImpl(std::move(packet)); }

  std::size_t GetSendRate() { return impl()->GetSendRateImpl(); }

  std::size_t GetReceiveRate() { return impl()->GetReceiveRateImpl(); }

 private:
  explicit BaseNetInterface(Config config)
      : config_(std::move(config)), recv_ip_packet_callback_(nullptr) {}

  Implementation* impl() { return static_cast<Implementation*>(this); }

 public:
  [[nodiscard]] const std::string& Name() const noexcept {
    return config_.name;
  }

  [[nodiscard]] const pcpp::IPv4Address& IPv4Addr() const noexcept {
    return config_.ipv4_addr;
  }

  [[nodiscard]] int IPv4Netmask() const noexcept {
    return config_.ipv4_netmask;
  }

  [[nodiscard]] const pcpp::IPv6Address& IPv6Addr() const noexcept {
    return config_.ipv6_addr;
  }

  int IPv6Netmask() const noexcept { return config_.ipv6_netmask; }

  void SetRecvIPPacketCallback(const NewIPPacketCallback& callback) noexcept {
    recv_ip_packet_callback_ = callback;
  }

  [[nodiscard]] NewIPPacketCallback GetRecvIPPacketCallback() const {
    return recv_ip_packet_callback_;
  }

 private:
  Config config_;
  NewIPPacketCallback recv_ip_packet_callback_;
};

#if defined(__APPLE__) || defined(__linux__)

class PosixTunInterface final : public BaseNetInterface<PosixTunInterface> {
 public:
  friend BaseNetInterface;

  using Config = BaseNetInterface::Config;

  explicit PosixTunInterface(Config config)
      : BaseNetInterface(std::move(config)),
        mtu_(FPTN_MTU_SIZE),
        running_(false) {}

  ~PosixTunInterface() { StopImpl(); }

 protected:
  bool StartImpl() noexcept {
    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    try {
      tun_ = std::make_unique<tuntap::tun>();
      tun_->name(Name());
      /* set IPv6 */
      tun_->ip(IPv6Addr().toString(), IPv6Netmask());
      /* set IPv4 */
      tun_->ip(IPv4Addr().toString(), IPv4Netmask());
      tun_->nonblocking(true);
      tun_->mtu(FPTN_MTU_SIZE);
      tun_->up();
      running_ = true;
      thread_ = std::thread(&PosixTunInterface::run, this);
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

    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    // cppcheck-suppress identicalConditionAfterEarlyExit
    if (!running_) {  // Double-check after acquiring lock
      return false;
    }

    if (thread_.joinable() && tun_) {
      running_ = false;
      thread_.join();
      tun_.reset();
    }
    return true;
  }

  bool SendImpl(IPPacketPtr packet) noexcept {
    if (!running_ || !packet || !packet->Size() || !tun_) {
      return false;
    }

    const std::lock_guard<std::mutex> lock(mutex_);  // mutex

    if (running_) {
      const auto* raw_packet = packet->GetRawPacket();
      const void* data = static_cast<const void*>(raw_packet->getRawData());
      const auto len = raw_packet->getRawDataLen();

      // send data
      const auto bytes_written = tun_->write(const_cast<void*>(data), len);

      // calculate rate
      send_rate_calculator_.Update(bytes_written);

      return bytes_written == len;
    }
    return false;
  }

  std::size_t GetSendRateImpl() const noexcept {
    return send_rate_calculator_.GetRateForSecond();
  }

  std::size_t GetReceiveRateImpl() const noexcept {
    return receive_rate_calculator_.GetRateForSecond();
  }

  void run() {
    auto data = std::make_unique<std::uint8_t[]>(mtu_);
    std::uint8_t* buffer = data.get();

    const auto callback = GetRecvIPPacketCallback();
    while (running_) {
      const int size = tun_->read(static_cast<void*>(buffer), mtu_);
      if (size > 0 && running_) {
        auto packet = IPPacket::Parse(buffer, size);
        if (running_ && packet != nullptr && callback) {
          receive_rate_calculator_.Update(packet->Size());  // calculate rate
          callback(std::move(packet));
        }
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

 private:
  mutable std::mutex mutex_;

  const std::uint16_t mtu_;

  std::atomic<bool> running_;
  std::thread thread_;
  std::unique_ptr<tuntap::tun> tun_;
  DataRateCalculator send_rate_calculator_;
  DataRateCalculator receive_rate_calculator_;
};

using TunInterface = PosixTunInterface;

#elif _WIN32

class WindowsTunInterface final : public BaseNetInterface<WindowsTunInterface> {
 public:
  friend BaseNetInterface;
  using Config = BaseNetInterface::Config;

  explicit WindowsTunInterface(Config config)
      : BaseNetInterface(std::move(config)),
        running_(false),
        wintun_(nullptr),
        adapter_(0),
        session_(0),
        ip_context_(0),
        ip_instance_(0) {
    wintun_ = InitializeWintun();
    UuidCreate(&guid_);
  }

  ~WindowsTunInterface() { StopImpl(); }

 protected:
  bool StartImpl() {
    if (!wintun_) {
      return false;
    }
    SPDLOG_INFO("WINTUN: {} version loaded",
        ParseWinTunVersion(WintunGetRunningDriverVersion()));

    // --- open adapter ---
    const std::wstring interface_name = ToWString(Name());
    adapter_ = WintunCreateAdapter(
        interface_name.c_str(), interface_name.c_str(), &guid_);
    if (!adapter_) {
      SPDLOG_ERROR("Network adapter wasn't created!");
      return false;
    }
    if (!SetIPv4AndNetmask(IPv4Addr(), IPv4Netmask())) {
      return false;
    }

    if (!SetIPv6AndNetmask(IPv6Addr(), IPv6Netmask())) {
      // pass IPv6
      // return false;
    }
    // --- start session ---
    const int capacity = 0x20000;
    session_ = WintunStartSession(adapter_, capacity);
    if (!session_) {
      SPDLOG_ERROR("Open sessoion error");
      return false;
    }
    // --- start thread ---
    running_ = true;
    thread_ = std::thread(&WindowsTunInterface::run, this);
    return thread_.joinable();
  }

  bool StopImpl() {
    if (running_ && thread_.joinable()) {
      running_ = false;
      thread_.join();

      if (adapter_) {
        WintunCloseAdapter(adapter_);
        adapter_ = nullptr;
      }
      WintunDeleteDriver();
      return true;
    }
    return false;
  }

  bool SendImpl(IPPacketPtr packet) {
    if (!running_ || !session_ || !packet || !packet->Size()) {
      return false;
    }

    const auto* raw_packet = packet->GetRawPacket();
    if (!raw_packet) {
      return false;
    }

    const auto len = raw_packet->getRawDataLen();
    const BYTE* packet_data =
        static_cast<const BYTE*>(raw_packet->getRawData());

    BYTE* send_buffer =
        WintunAllocateSendPacket(session_, static_cast<DWORD>(len));
    if (!send_buffer || !packet_data || len == 0) {
      return false;
    }

    std::memcpy(send_buffer, packet_data, len);
    WintunSendPacket(session_, send_buffer);

    send_rate_calculator_.Update(len);
    return true;
  }

  std::size_t GetSendRateImpl() const {
    return send_rate_calculator_.GetRateForSecond();
  }

  std::size_t GetReceiveRateImpl() const {
    return receive_rate_calculator_.GetRateForSecond();
  }

  // cppcheck-suppress unusedPrivateFunction
  bool SetIPv4AndNetmask(const pcpp::IPv4Address& addr, const int mask) {
    const std::string ipaddr = addr.toString();
    MIB_UNICASTIPADDRESS_ROW address_row;

    InitializeUnicastIpAddressEntry(&address_row);
    WintunGetAdapterLUID(adapter_, &address_row.InterfaceLuid);

    address_row.Address.Ipv4.sin_family = AF_INET;
    address_row.OnLinkPrefixLength = static_cast<BYTE>(mask);
    address_row.DadState = IpDadStatePreferred;

    if (1 != inet_pton(AF_INET, ipaddr.c_str(),
                 &(address_row.Address.Ipv4.sin_addr))) {
      SPDLOG_ERROR("Wrong IPv4 address");
      return false;
    }
    const auto res = CreateUnicastIpAddressEntry(&address_row);
    if (res != ERROR_SUCCESS && res != ERROR_OBJECT_ALREADY_EXISTS) {
      SPDLOG_ERROR("Failed to set {} IPv4 address", ipaddr);
      return false;
    }
    return true;
  }
  // cppcheck-suppress unusedPrivateFunction
  bool SetIPv6AndNetmask(const pcpp::IPv6Address& addr, const int mask) {
    const std::string ipaddr = addr.toString();
    MIB_UNICASTIPADDRESS_ROW address_row;

    InitializeUnicastIpAddressEntry(&address_row);
    WintunGetAdapterLUID(adapter_, &address_row.InterfaceLuid);

    address_row.Address.Ipv6.sin6_family = AF_INET6;
    address_row.OnLinkPrefixLength = static_cast<BYTE>(mask);
    address_row.DadState = IpDadStatePreferred;

    if (1 != inet_pton(AF_INET6, ipaddr.c_str(),
                 &(address_row.Address.Ipv6.sin6_addr))) {
      SPDLOG_ERROR("Wrong IPv6 address");
      return false;
    }
    const auto res = CreateUnicastIpAddressEntry(&address_row);
    if (res != ERROR_SUCCESS && res != ERROR_OBJECT_ALREADY_EXISTS) {
      SPDLOG_ERROR("Failed to set {} IPv6 address", ipaddr);
      return false;
    }
    return true;
  }

  void run() {
    std::uint8_t buffer[65536] = {0};
    DWORD size = sizeof(buffer);
    const auto callback = GetRecvIPPacketCallback();
    while (running_) {
      if (ERROR_SUCCESS == ReadPacketNonblock(session_, buffer, &size)) {
        auto packet = IPPacket::Parse(buffer, size);
        if (packet != nullptr && callback) {
          receive_rate_calculator_.Update(packet->Size());  // calculate rate
          callback(std::move(packet));
        }
      }
    }
  }

  // cppcheck-suppress unusedFunction
  std::wstring ToWString(const std::string& s) {
    return std::wstring(s.begin(), s.end());
  }

  // cppcheck-suppress unusedFunction
  std::string ParseWinTunVersion(DWORD version_number) {
    return std::to_string((version_number >> 16) & 0xff) + "." +
           std::to_string((version_number >> 0) & 0xff);
  }

  // cppcheck-suppress unusedFunction
  int ReadPacketNonblock(
      WINTUN_SESSION_HANDLE session, BYTE* buff, DWORD* size) {
    static constexpr size_t retry_amount = 20;
    while (running_) {
      for (size_t i = 0; i < retry_amount; i++) {
        DWORD packet_size;
        BYTE* packet = WintunReceivePacket(session, &packet_size);
        if (packet && running_) {
          memcpy(buff, packet, packet_size);
          *size = packet_size;
          WintunReleaseReceivePacket(session, packet);
          return ERROR_SUCCESS;
        } else if (GetLastError() == ERROR_NO_MORE_ITEMS) {
          // We retry before blocking
          continue;
        } else {
          return ERROR_INVALID_FUNCTION;
        }
      }
      WaitForSingleObject(WintunGetReadWaitEvent(session),
          10);  // Wait for a maximum of 10 milliseconds
    }
    return ERROR_INVALID_FUNCTION;
  }

  HMODULE InitializeWintun() {
    HMODULE wintun = LoadLibraryExW(L"wintun.dll", nullptr,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!wintun) {
      SPDLOG_ERROR("WINTUN NOT FOUND!");
      return nullptr;
    }
#define X(Name)                                                              \
  ((*(reinterpret_cast<FARPROC*>(&Name)) = GetProcAddress(wintun, #Name)) == \
      nullptr)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) ||
        X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) ||
        X(WintunSetLogger) || X(WintunStartSession) || X(WintunEndSession) ||
        X(WintunGetReadWaitEvent) || X(WintunReceivePacket) ||
        X(WintunReleaseReceivePacket) || X(WintunAllocateSendPacket) ||
        X(WintunSendPacket)) {
      DWORD last_error = GetLastError();
      FreeLibrary(wintun);
      SetLastError(last_error);
      SPDLOG_ERROR("Error whilst loading the lib: {}", last_error);
      return nullptr;
    }
#undef X
    SPDLOG_INFO("Wintun initialization successful");
    return wintun;
  }

 private:
  WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter = nullptr;
  WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter = nullptr;
  WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter = nullptr;
  WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID = nullptr;
  WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion =
      nullptr;
  WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver = nullptr;
  WINTUN_SET_LOGGER_FUNC* WintunSetLogger = nullptr;
  WINTUN_START_SESSION_FUNC* WintunStartSession = nullptr;
  WINTUN_END_SESSION_FUNC* WintunEndSession = nullptr;
  WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent = nullptr;
  WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket = nullptr;
  WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket = nullptr;
  WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket = nullptr;
  WINTUN_SEND_PACKET_FUNC* WintunSendPacket = nullptr;

 private:
  std::atomic<bool> running_;
  std::thread thread_;

  GUID guid_;
  HMODULE wintun_;
  WINTUN_ADAPTER_HANDLE adapter_;
  WINTUN_SESSION_HANDLE session_;
  ULONG ip_context_;
  ULONG ip_instance_;

  DataRateCalculator send_rate_calculator_;
  DataRateCalculator receive_rate_calculator_;
};

using TunInterface = WindowsTunInterface;
#endif

using TunInterfacePtr = std::unique_ptr<TunInterface>;
}  // namespace fptn::common::network
