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

#include <glog/logging.h>

#include <pcapplusplus/MacAddress.h>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/ArpLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>

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

    class IPPacket final
    {
    public:

        static std::unique_ptr<IPPacket> parse(std::string strdata, std::uint32_t clientId = PACKET_UNDEFINED_CLIENT_ID)
        {
            auto packet =  std::make_unique<IPPacket>(std::move(strdata), clientId);
            if (nullptr != packet->ipLayer()) {
                return packet;
            }
            return nullptr;
        }

        static std::unique_ptr<IPPacket> parse(const std::uint8_t *data, std::size_t size, std::uint32_t clientId = PACKET_UNDEFINED_CLIENT_ID)
        {
            std::string strdata((const char*)data, size);
            return parse(std::move(strdata), clientId);
        }
    public:
        IPPacket(std::string data, std::uint32_t clientId)
            :
                packetData_(std::move(data)),
                clientId_(clientId),
                rawPacket_(
                    (const std::uint8_t*)packetData_.c_str(),
                    (int)packetData_.size(),
                    timeval { 0, 0 },
                    false,
                    pcpp::LINKTYPE_IPV4
                ),
                parsedPacket_(&rawPacket_, false),
                ipLayer_(parsedPacket_.getLayerOfType<pcpp::IPv4Layer>())
        {
        }
        ~IPPacket() = default;

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
            ipLayer_->computeCalculateFields();
        }

        void setClientId(std::uint32_t clientId) noexcept
        {
            clientId_ = clientId;
        }
        
        std::uint32_t clientId() const noexcept
        {
            return clientId_;
        }

        pcpp::Packet& pkt() noexcept
        {
            return parsedPacket_;
        }
        
        pcpp::IPv4Layer* ipLayer() noexcept
        {
            return ipLayer_;
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

        bool isDnsPacket() const noexcept
        {
            auto udp = parsedPacket_.getLayerOfType<pcpp::UdpLayer>();
            if (udp) {
                if (ntohs(udp->getUdpHeader()->portSrc) == 53 || ntohs(udp->getUdpHeader()->portDst) == 53) {
                    return true;
                }
                return false;
            }
            auto tcp = parsedPacket_.getLayerOfType<pcpp::TcpLayer>();
            if (tcp) {
                if (ntohs(tcp->getTcpHeader()->portSrc) == 53 || ntohs(tcp->getTcpHeader()->portDst) == 53) {
                    return true;
                }
            }
            return false;
        }
    private:
        std::string packetData_;
        std::uint32_t clientId_;
        pcpp::RawPacket rawPacket_;
        pcpp::Packet parsedPacket_;

        pcpp::IPv4Layer* ipLayer_;
    };

    using IPPacketPtr = std::unique_ptr<IPPacket>;
}
