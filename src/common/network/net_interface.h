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
    const std::lock_guard<std::mutex> lock(mutex_);

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
    const std::lock_guard<std::mutex> lock(mutex_);

    const auto intervalCount = interval_.count();
    if (intervalCount) {
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

class BaseNetInterface {
 public:
  virtual bool Start() noexcept = 0;
  virtual bool Stop() noexcept = 0;
  virtual bool Send(IPPacketPtr packet) noexcept = 0;
  [[nodiscard]] virtual std::size_t GetSendRate() const noexcept = 0;
  [[nodiscard]] virtual std::size_t GetReceiveRate() const noexcept = 0;

 public:
  explicit BaseNetInterface(std::string  name,
      const pcpp::IPv4Address& ipv4_addr,
      const int ipv4_netmask,
      const pcpp::IPv6Address& ipv6_addr,
      const int ipv6_netmask,
      NewIPPacketCallback callback = nullptr)
      : name_(std::move(name)),
        ipv4_addr_(ipv4_addr),
        ipv4_netmask_(ipv4_netmask),
        ipv6_addr_(ipv6_addr),
        ipv6_netmask_(ipv6_netmask),
        new_ippacket_callback(std::move(callback)) {}

  virtual ~BaseNetInterface() = default;

  [[nodiscard]] const std::string& Name() const noexcept { return name_; }

  [[nodiscard]] const pcpp::IPv4Address& IPv4Addr() const noexcept {
    return ipv4_addr_;
  }

  [[nodiscard]] int IPv4Netmask() const noexcept { return ipv4_netmask_; }

  [[nodiscard]] const pcpp::IPv6Address& IPv6Addr() const noexcept {
    return ipv6_addr_;
  }

  int IPv6Netmask() const noexcept { return ipv6_netmask_; }

  void SetNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept {
    new_ippacket_callback = callback;
  }

 private:
  const std::string name_;
  /* IPv4 */
  const pcpp::IPv4Address ipv4_addr_;
  const int ipv4_netmask_;
  /* IPv6 */
  const pcpp::IPv6Address ipv6_addr_;
  const int ipv6_netmask_;

 protected:
  NewIPPacketCallback new_ippacket_callback;
};

using BaseNetInterfacePtr = std::unique_ptr<BaseNetInterface>;

#if defined(__APPLE__) || defined(__linux__)

class PosixTunInterface final : public BaseNetInterface {
 public:
  explicit PosixTunInterface(const std::string& name,
      const pcpp::IPv4Address& ipv4Addr,
      const int ipv4Netmask,
      const pcpp::IPv6Address& ipv6Addr,
      const int ipv6Netmask,
      const NewIPPacketCallback& callback = nullptr)
      : BaseNetInterface(
            name, ipv4Addr, ipv4Netmask, ipv6Addr, ipv6Netmask, callback),
        mtu_(FPTN_MTU_SIZE),
        running_(false) {}

  ~PosixTunInterface() override = default;

  bool Start() noexcept override {
    try {
      tun_ = std::make_unique<tuntap::tun>();
      tun_->name(Name());
      /* set IPv6 */
      tun_->ip(IPv6Addr().toString(), IPv6Netmask());
      /* set IPv4 */
      tun_->ip(IPv4Addr().toString(), IPv4Netmask());

      tun_->nonblocking(true);
      tun_->mtu(mtu_);
      tun_->up();

      running_ = true;
      thread_ = std::thread(&PosixTunInterface::run, this);
      return thread_.joinable();
    } catch (const std::exception& ex) {
      SPDLOG_ERROR("Error start: {}", ex.what());
    }
    return false;
  }

  bool Stop() noexcept override {
    if (thread_.joinable() && running_ && tun_) {
      running_ = false;
      thread_.join();
      tun_.reset();
      return true;
    }
    return false;
  }

  bool Send(IPPacketPtr packet) noexcept override {
    if (running_ && packet && packet->Size()) {
      send_rate_calculator_.Update(packet->Size());  // calculate rate
      std::vector<std::uint8_t> serialized = packet->Serialize();
      return static_cast<std::size_t>(tun_->write(
                 serialized.data(), serialized.size())) == serialized.size();
    }
    return false;
  }

  std::size_t GetSendRate() const noexcept override {
    return send_rate_calculator_.GetRateForSecond();
  }

  std::size_t GetReceiveRate() const noexcept override {
    return receive_rate_calculator_.GetRateForSecond();
  }

 protected:
  void run() noexcept {
    std::unique_ptr<std::uint8_t[]> data =
        std::make_unique<std::uint8_t[]>(mtu_);
    std::uint8_t* buffer = data.get();
    while (running_) {
      const int size = tun_->read(static_cast<void*>(buffer), mtu_);
      if (size > 0 && running_) {
        auto packet = IPPacket::Parse(buffer, size);
        if (packet != nullptr && new_ippacket_callback && running_) {
          receive_rate_calculator_.Update(packet->Size());  // calculate rate
          new_ippacket_callback(std::move(packet));
        }
      } else {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }
  }

 private:
  const std::uint16_t mtu_;
  std::atomic<bool> running_;
  std::thread thread_;
  std::unique_ptr<tuntap::tun> tun_;
  DataRateCalculator send_rate_calculator_;
  DataRateCalculator receive_rate_calculator_;
};

using TunInterface = PosixTunInterface;

#elif _WIN32

class WindowsTunInterface : public BaseNetInterface {
 public:
  WindowsTunInterface(const std::string& name,
      const pcpp::IPv4Address& ipv4_addr,
      const int ipv4_netmask,
      const pcpp::IPv6Address& ipv6_addr,
      const int ipv6_netmask,
      const NewIPPacketCallback& callback = nullptr)
      : BaseNetInterface(
            name, ipv4_addr, ipv4_netmask, ipv6_addr, ipv6_netmask, callback),
        running_(false),
        wintun_(nullptr),
        adapter_(0),
        session_(0),
        ip_context_(0),
        ip_instance_(0) {
    wintun_ = InitializeWintun();
    UuidCreate(&guid_);
  }

  ~WindowsTunInterface() override = default;

  bool Start() noexcept override {
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

  bool Stop() noexcept override {
    if (thread_.joinable() && running_) {
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

  bool Send(IPPacketPtr packet) noexcept override {
    if (running_ && session_ && packet && packet->Size()) {
      send_rate_calculator_.Update(packet->Size());
      BYTE* data = WintunAllocateSendPacket(
          session_, static_cast<DWORD>(packet->Size()));
      if (data) {
        const std::vector<std::uint8_t> serialized = packet->Serialize();
        std::memcpy(data, serialized.data(), serialized.size());
        WintunSendPacket(session_, data);
        return true;
      }
    }
    return false;
  }
  std::size_t GetSendRate() const noexcept override {
    return send_rate_calculator_.GetRateForSecond();
  }

  std::size_t GetReceiveRate() const noexcept override {
    return receive_rate_calculator_.GetRateForSecond();
  }

 protected:
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

  void run() noexcept {
    std::uint8_t buffer[65536] = {0};
    DWORD size = sizeof(buffer);
    while (running_) {
      if (ERROR_SUCCESS == ReadPacketNonblock(session_, buffer, &size)) {
        auto packet = IPPacket::Parse(buffer, size);
        if (packet != nullptr && new_ippacket_callback) {
          receive_rate_calculator_.Update(packet->Size());  // calculate rate
          new_ippacket_callback(std::move(packet));
        }
      }
    }
  }

  // cppcheck-suppress unusedFunction
  inline std::wstring ToWString(const std::string& s) {
    return std::wstring(s.begin(), s.end());
  }

  // cppcheck-suppress unusedFunction
  inline std::string ParseWinTunVersion(DWORD version_number) {
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
