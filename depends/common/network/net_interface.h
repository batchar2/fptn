#pragma once

#include <mutex>
#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <functional>

#include <glog/logging.h>
#include <common/data/channel.h>

#if defined(__APPLE__) || defined(__linux__)
    #include <tuntap++.hh>
#elif _WIN32
    #include <Ws2tcpip.h>
    #include <windows.h>
    #include <objbase.h>
    #include <winsock2.h>
    #include <Iprtrmib.h>
    #include <iphlpapi.h>
    #include <WinError.h>

    #include <wintun.h>
#endif

#include "ip_packet.h"


namespace fptn::common::network
{
    class DataRateCalculator
    {
    public:
        explicit DataRateCalculator(std::chrono::milliseconds interval = std::chrono::milliseconds(1000))
                : interval_(interval),
                  bytes_(0),
                  lastUpdateTime_(std::chrono::steady_clock::now()),
                  rate_(0)
        {
        }
        void update(std::size_t len) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto now = std::chrono::steady_clock::now();
            std::chrono::duration<double> elapsed = now - lastUpdateTime_;
            bytes_ += len;
            if (elapsed >= interval_) {
                rate_ = static_cast<std::size_t>(bytes_ / elapsed.count());
                lastUpdateTime_ = now;
                bytes_ = 0;
            }
        }
        std::size_t getRateForSecond() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
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

    
    class BaseNetInterface
    {
    public:
        virtual bool start() noexcept = 0;
        virtual bool stop() noexcept = 0;
        virtual bool send(IPPacketPtr packet) noexcept = 0;
        virtual std::size_t getSendRate() const noexcept = 0;
        virtual std::size_t getReceiveRate() const noexcept = 0;
    public:
        explicit BaseNetInterface(
            const std::string &name,
            const pcpp::IPv4Address &addr,
            const int netmask,
            const NewIPPacketCallback& callback = nullptr
        )
            :
                name_(name),
                addr_(addr),
                netmask_(netmask),
                newIPPktCallback(callback)
        {
        }

        virtual ~BaseNetInterface() = default;

        const std::string& name() const 
        {
            return name_;
        }

        const pcpp::IPv4Address& addr() const 
        {
            return addr_;
        }

        int netmask() const 
        {
            return netmask_;
        }

        void setNewIPPacketCallback(const NewIPPacketCallback &callback) noexcept
        {
            newIPPktCallback = callback;
        }
    protected:
        NewIPPacketCallback newIPPktCallback;
    private:
        const std::string &name_;
        const pcpp::IPv4Address &addr_;
        const int netmask_;

    };

    using BaseNetInterfacePtr = std::unique_ptr<BaseNetInterface>;


#if defined(__APPLE__) || defined(__linux__)

    class PosixTunInterface final : public BaseNetInterface
    {
    public:
        explicit PosixTunInterface(
            const std::string &name,
            const pcpp::IPv4Address &addr,
            const int netmask,
            const NewIPPacketCallback &callback = nullptr
        )
            :
                BaseNetInterface(name, addr, netmask, callback),
                mtu_(1500),
                running_(false)
        {
        }

        virtual ~PosixTunInterface()
        {
            stop();
        }

        virtual bool start() noexcept override
        {
            try {
                tun_ = std::make_unique<tuntap::tun>();
                tun_->name(name());
                tun_->ip(addr().toString(), netmask());
                tun_->mtu(mtu_);
                tun_->nonblocking(true);
                tun_->up();

                running_ = true;
                thread_ = std::thread(&PosixTunInterface::run, this);
                return thread_.joinable();
            } catch (const std::exception &ex) {
                LOG(ERROR) << "Error start: " << ex.what() << std::endl;
            }
            return false;
        }

        virtual bool stop() noexcept override
        {
            if (thread_.joinable() && running_ && tun_) {
                running_ = false;
                thread_.join();
                tun_.reset();
                return true;
            }
            return false;
        }

        virtual bool send(IPPacketPtr packet) noexcept override
        {
            if (running_ && packet && packet->size()) {
                sendRateCalculator_.update(packet->size()); // calculate rate
                std::vector<std::uint8_t> serialized = packet->serialize();
                return tun_->write(serialized.data(), serialized.size()) == serialized.size();
            }
            return false;
        }

        virtual std::size_t getSendRate() const noexcept override
        {
            return sendRateCalculator_.getRateForSecond();
        }

        virtual std::size_t getReceiveRate() const noexcept override
        {
            return receiveRateCalculator_.getRateForSecond();
        }
    private:
        void run() noexcept
        {
            std::unique_ptr<std::uint8_t[]> data = std::make_unique<std::uint8_t[]>(mtu_);
            std::uint8_t *buffer = data.get();
            while(running_) {
                const int size = tun_->read(static_cast<void*>(buffer), mtu_);
                if (size > 0 && running_) {
                    auto packet = IPPacket::parse(buffer, size);;
                    if (packet != nullptr && newIPPktCallback) {
                        receiveRateCalculator_.update(packet->size()); // calculate rate
                        newIPPktCallback(std::move(packet));
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

        DataRateCalculator sendRateCalculator_;
        DataRateCalculator receiveRateCalculator_;
    };

    using TunInterface = PosixTunInterface;

#elif _WIN32

    class WindowsTunInterface final : public BaseNetInterface
    {
    public:
        WindowsTunInterface(
                const std::string &name,
                const pcpp::IPv4Address &addr,
                const int netmask,
                const NewIPPacketCallback &callback = nullptr
        )
            :   
                BaseNetInterface(name, addr, netmask, callback),
                mtu_(65536),
                running_(false),
                wintun_(nullptr),
                adapter_(0),
                session_(0),
                ipContext_(0),
                ipInstance_(0)
        {
            wintun_ = InitializeWintun();
            UuidCreate(&guid_);
        }
        virtual ~WindowsTunInterface()
        {
            stop();
        }
        virtual bool start() noexcept override
        {
            if (!wintun_) {
                return false;
            }
            LOG(INFO) << "WINTUN: " << parseWinTunVersion(WintunGetRunningDriverVersion()) << " version loaded";
            
            // --- open adapter ---
            const std::wstring interfaceName = toWString(name());
            adapter_ = WintunCreateAdapter(
                interfaceName.c_str(),
                interfaceName.c_str(),
                &guid_
            );
            if (!adapter_) {
                LOG(ERROR) << "Network adapter wasn't created!";
            }

            const std::string ipaddr = this->addr().toString();
            MIB_UNICASTIPADDRESS_ROW addressRow;
            InitializeUnicastIpAddressEntry(&addressRow);
            WintunGetAdapterLUID(adapter_, &addressRow.InterfaceLuid);
            addressRow.Address.Ipv4.sin_family = AF_INET;
            addressRow.OnLinkPrefixLength = (BYTE)this->netmask();
            auto res = inet_pton(AF_INET, ipaddr.c_str(), &(addressRow.Address.Ipv4.sin_addr));
            if (res != 1) {
                LOG(ERROR) << "Wrong address";
                return false;
            }
            auto res2 = CreateUnicastIpAddressEntry(&addressRow);
            if (res2 != ERROR_SUCCESS && res2 != ERROR_OBJECT_ALREADY_EXISTS) {
                LOG(ERROR) << "Failed to set " << ipaddr << " IP address";
                return false;
            }
            // --- start session ---
            const int capacity = 0x20000;
            session_ = WintunStartSession(adapter_, capacity);
            if (!session_) {
                LOG(ERROR) << "Open sessoion error";
                return false;
            }
            // --- start thread ---
            running_ = true;
            thread_ = std::thread(&WindowsTunInterface::run, this);
            return thread_.joinable();
        }
        virtual bool stop() noexcept override
        {
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

        virtual bool send(IPPacketPtr packet) noexcept override
        {
            if (running_ && session_ && packet && packet->size()) {
                sendRateCalculator_.update(packet->size()); 
                BYTE *data = WintunAllocateSendPacket(session_, packet->size());
                if (data) {
                    std::vector<std::uint8_t> serialized = packet->serialize();
                    std::memcpy(data, serialized.data(), serialized.size());
                    WintunSendPacket(session_, data);
                    return true;
                }
            }
            return false;            
        }

        virtual std::size_t getSendRate() const noexcept override
        {
            return sendRateCalculator_.getRateForSecond();
        }

        virtual std::size_t getReceiveRate() const noexcept override
        {
            return receiveRateCalculator_.getRateForSecond();
        }

    private:
        void run() noexcept
        {
            std::unique_ptr<std::uint8_t[]> data = std::make_unique<std::uint8_t[]>(mtu_);
            std::uint8_t *buffer = data.get();
            DWORD bufferSize = mtu_;

            while(running_) {
                bufferSize = mtu_;
                if (ERROR_SUCCESS == readPacketNonblock(session_, buffer, &mtu_)) {
                    auto packet = IPPacket::parse(buffer, bufferSize);
                    if (packet != nullptr && newIPPktCallback) {
                        receiveRateCalculator_.update(packet->size()); // calculate rate
                        newIPPktCallback(std::move(packet));
                    }
                }
            }
        }

        inline std::wstring toWString(const std::string& s) 
        {
            return std::wstring(s.begin(), s.end());
        }

        inline std::string parseWinTunVersion(DWORD versionNumber)
        {
            return std::to_string((versionNumber >> 16) & 0xff) + "." + std::to_string((versionNumber >> 0) & 0xff);
        }
        
        int readPacketNonblock(WINTUN_SESSION_HANDLE session, BYTE *buff, DWORD *size)
        {
            static constexpr size_t retryAmount = 20;
			while (running_) {
				for (size_t i = 0; i < retryAmount; i++) {
					DWORD packetSize;
					BYTE* packet = WintunReceivePacket(session, &packetSize);
					if (packet && running_ && *size > packetSize) {
                        memcpy(buff, packet, packetSize);
                        *size = packetSize;
                        WintunReleaseReceivePacket(session, packet);
                        return ERROR_SUCCESS;
					} else if (GetLastError() == ERROR_NO_MORE_ITEMS) {
						// We retry before blocking
						continue;
					} else {
						return ERROR_INVALID_FUNCTION;
					}
				}
				WaitForSingleObject(WintunGetReadWaitEvent(session), 10); // Wait for a maximum of 10 milliseconds
			}
			return ERROR_INVALID_FUNCTION;
        }

        HMODULE InitializeWintun()
        {
            HMODULE wintun = LoadLibraryExW(L"wintun.dll", nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (!wintun) {
                LOG(ERROR) << "WINTUN NOT FOUND!";
                return nullptr;
            }
            #define X(Name) ((*(FARPROC *)&Name = GetProcAddress(wintun, #Name)) == nullptr)
            if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
                X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
                X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
                X(WintunAllocateSendPacket) || X(WintunSendPacket)
            )
            #undef X
            {
                DWORD LastError = GetLastError();
                FreeLibrary(wintun);
                SetLastError(LastError);
                LOG(ERROR) << "Error whilst loading the lib: " << LastError;
                return nullptr;
            }
            LOG(INFO) << "Wintun initialization successful";
            return wintun;
        }
    private:
        WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter = nullptr;
        WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter = nullptr;
        WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter = nullptr;
        WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID = nullptr;
        WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion = nullptr;
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
        const std::uint16_t mtu_;
        std::atomic<bool> running_;
        std::thread thread_;
        
        GUID guid_;
        HMODULE wintun_;
		WINTUN_ADAPTER_HANDLE adapter_;
		WINTUN_SESSION_HANDLE session_;
		ULONG ipContext_;
		ULONG ipInstance_;

        DataRateCalculator sendRateCalculator_;
        DataRateCalculator receiveRateCalculator_;
    };

    using TunInterface = WindowsTunInterface;
#endif

    using TunInterfacePtr = std::unique_ptr<TunInterface>;
}
