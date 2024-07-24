#pragma once

#include <string>
#include <memory>
#include <vector>

#include <pcapplusplus/Packet.h>
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


namespace fptn::common::network
{

    #define PACKET_UNDEFINED_CLIENT_ID        (static_cast<std::uint32_t>(-1))
    

    class IPPacket final
    {
    public:
        static std::unique_ptr<IPPacket> parse(const std::uint8_t *data, std::size_t size, std::uint32_t clientId = PACKET_UNDEFINED_CLIENT_ID)
        {
            /* TODO REWRITE */
            pcpp::RawPacket rawPacket(
                (const std::uint8_t*)data,
                (int)size,
                timeval { 0, 0 },
                false,
                pcpp::LINKTYPE_IPV4
            );
            pcpp::Packet parsedPacket(&rawPacket, false);
            if (parsedPacket.isPacketOfType(pcpp::IPv4) || parsedPacket.isPacketOfType(pcpp::IP)) {
                if (parsedPacket.getLayerOfType<pcpp::IPv4Layer>()) {
                    return std::make_unique<IPPacket>(
                        std::string((char*)data, size),
                        clientId
                    );
                }
            }
            return nullptr;
        }
    public:
        IPPacket(std::string packetData, std::uint32_t clientId)
            : 
                packetData_(std::move(packetData)), 
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

        void computeCalculateFields()
        {
            ipLayer_->computeCalculateFields();
            pcpp::TcpLayer* tcpLayer = parsedPacket_.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer) {
                tcpLayer->computeCalculateFields();
            }
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
            return std::vector<std::uint8_t>(raw->getRawData(), raw->getRawData() + raw->getRawDataLen());
        }
        std::size_t size() const 
        {
            return packetData_.size();
        }
    private:
        std::string packetData_;
        std::uint32_t clientId_;
        pcpp::RawPacket rawPacket_;
        pcpp::Packet parsedPacket_;
        
        std::size_t size_;
        pcpp::IPv4Layer* ipLayer_;
    };

    using IPPacketPtr = std::unique_ptr<IPPacket>;
}
