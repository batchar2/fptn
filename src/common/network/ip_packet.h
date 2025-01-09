#pragma once

#include <string>
#include <memory>
#include <vector>
#include <cstdint>

#if _WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include <iostream>

#include <spdlog/spdlog.h>

#include <pcapplusplus/MacAddress.h>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/ArpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/IcmpV6Layer.h>

#ifdef TCPOPT_CC
#undef TCPOPT_CC
#endif // TCPOPT_CC
#ifdef TCPOPT_CCNEW
#undef TCPOPT_CCNEW
#endif // TCPOPT_CCNEW
#ifdef TCPOPT_CCECHO
#undef TCPOPT_CCECHO
#endif // TCPOPT_CCECHO

#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>


namespace fptn::common::network
{

    #define PACKET_UNDEFINED_CLIENT_ID   (static_cast<std::uint32_t>(-1))

    inline bool checkIPv4(const std::string& buffer)
    {
        return (static_cast<uint8_t>(buffer[0]) >> 4) == 4;
    }

    inline bool checkIPv6(const std::string& buffer)
    {
        return (static_cast<uint8_t>(buffer[0]) >> 4) == 6;
    }

    class IPPacket
    {
    public:
        static std::unique_ptr<IPPacket> parse(std::string buffer, std::uint32_t clientId = PACKET_UNDEFINED_CLIENT_ID)
        {
            if (buffer.empty()) {
                return nullptr;
            }
            if (checkIPv4(buffer)) {
                auto packet =  std::make_unique<IPPacket>(std::move(buffer), clientId, pcpp::LINKTYPE_IPV4);
                if (nullptr != packet->ipv4Layer()) {
                    return packet;
                }
            } else if (checkIPv6(buffer)) {
                auto packet =  std::make_unique<IPPacket>(std::move(buffer), clientId, pcpp::LINKTYPE_IPV6);
                if (nullptr != packet->ipv6Layer()) {
                    return packet;
                }
            }
            return nullptr;
        }

        static std::unique_ptr<IPPacket> parse(const std::uint8_t *data, std::size_t size, std::uint32_t clientId = PACKET_UNDEFINED_CLIENT_ID)
        {
            std::string buffer((const char*)data, size);
            return parse(std::move(buffer), clientId);
        }
    public:
        IPPacket(std::string data, std::uint32_t clientId, pcpp::LinkLayerType ipType)
            :
                packetData_(std::move(data)),
                clientId_(clientId),
                rawPacket_(
                    (const std::uint8_t*)packetData_.c_str(),
                    (int)packetData_.size(),
                    timeval { 0, 0 },
                    false,
                    ipType // pcpp::LINKTYPE_IPV4 or pcpp::LINKTYPE_IPV6
                ),
                parsedPacket_(&rawPacket_, false)
        {
            ipv4Layer_ = (pcpp::LINKTYPE_IPV4 == ipType)
                         ? parsedPacket_.getLayerOfType<pcpp::IPv4Layer>()
                         : nullptr;
            ipv6Layer_ = (pcpp::LINKTYPE_IPV6 == ipType)
                         ? parsedPacket_.getLayerOfType<pcpp::IPv6Layer>()
                         : nullptr;
        }

        virtual ~IPPacket() = default;

        void computeCalculateFields() noexcept
        {
            auto tcpLayer = parsedPacket_.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer) {
                tcpLayer->computeCalculateFields();
            } else {
                auto udpLayer = parsedPacket_.getLayerOfType<pcpp::UdpLayer>();
                if (udpLayer) {
                    udpLayer->computeCalculateFields();
                }
            }
            if (ipv4Layer_) {
                ipv4Layer_->computeCalculateFields();
            } else if (ipv6Layer_) {
                auto icmpLayer = parsedPacket_.getLayerOfType<pcpp::IcmpV6Layer>();
                if (icmpLayer) {
                    icmpLayer->computeCalculateFields();
                }
                ipv6Layer_->computeCalculateFields();
            }
        }

        void setClientId(std::uint32_t clientId) noexcept
        {
            clientId_ = clientId;
        }

        void setDstIPv4Address(const pcpp::IPv4Address& dst) noexcept
        {
            if (ipv4Layer_) {
                ipv4Layer_->getIPv4Header()->timeToLive -= 1;
                ipv4Layer_->setDstIPv4Address(dst);
            }
        }

        void setSrcIPv4Address(const pcpp::IPv4Address& src) noexcept
        {
            if (ipv4Layer_) {
                ipv4Layer_->getIPv4Header()->timeToLive -= 1;
                ipv4Layer_->setSrcIPv4Address(src);
            }
        }

        void setDstIPv6Address(const pcpp::IPv6Address& dst) noexcept
        {
            if (ipv6Layer_) {
                ipv6Layer_->setDstIPv6Address(dst);
            }
        }

        void setSrcIPv6Address(const pcpp::IPv6Address& src) noexcept
        {
            if (ipv6Layer_) {
                ipv6Layer_->setSrcIPv6Address(src);
            }
        }

        std::uint32_t clientId() const noexcept
        {
            return clientId_;
        }

        pcpp::Packet& pkt() noexcept
        {
            return parsedPacket_;
        }

        std::vector<std::uint8_t> serialize() noexcept
        {
            const auto raw = parsedPacket_.getRawPacket();
            return {raw->getRawData(), raw->getRawData() + raw->getRawDataLen()};
        }

        std::size_t size() const noexcept
        {
            return packetData_.size();
        }

        std::string toString() noexcept
        {
            const auto raw = parsedPacket_.getRawPacket();
            return {reinterpret_cast<const char*>(raw->getRawData()), static_cast<std::size_t>(raw->getRawDataLen())};
        }
    public:
        /* virtual functions for tests */
        virtual bool isIPv4() const noexcept
        {
            return ipv4Layer_ != nullptr;
        }

        virtual bool isIPv6() const noexcept
        {
            return ipv6Layer_ != nullptr;
        }

        virtual pcpp::IPv4Layer* ipv4Layer() noexcept
        {
            return ipv4Layer_;
        }

        virtual pcpp::IPv6Layer* ipv6Layer() noexcept
        {
            return ipv6Layer_;
        }
    protected:
        IPPacket()  // for tests
            : clientId_(PACKET_UNDEFINED_CLIENT_ID)
        {
        }
    private:
        std::string packetData_;
        std::uint32_t clientId_;
        pcpp::RawPacket rawPacket_;
        pcpp::Packet parsedPacket_;

        pcpp::IPv4Layer* ipv4Layer_ = nullptr;
        pcpp::IPv6Layer* ipv6Layer_ = nullptr;
    };

    using IPPacketPtr = std::unique_ptr<IPPacket>;
}
