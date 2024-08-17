#pragma once

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/EthLayer.h>

namespace fptn::common::network
{
    class IPPacket;

    class EthPacket final
    {
    public:
        static std::unique_ptr<IPPacket> extractIPPacket(const std::uint8_t *data, std::size_t size)
        {
            // TODO REWRITE IT!!!
            pcpp::RawPacket rawPacket(
                    data,
                    static_cast<int>(size),
                    timeval { 0, 0 },
                    false,
                    pcpp::LINKTYPE_ETHERNET
            );
            pcpp::Packet parsedPacket(&rawPacket, false);
            if (parsedPacket.isPacketOfType(pcpp::Ethernet)) {
                const pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
                if (ethLayer) {
                    const pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
                    if (ipLayer) {
                        std::string tmp(reinterpret_cast<const char*>(ipLayer->getData()), ipLayer->getDataLen());
                        return std::make_unique<IPPacket>(tmp);
                    }
                }
            }
            return nullptr;
        }

        static std::vector<std::uint8_t> serializeData(IPPacketPtr ipPacket, const pcpp::MacAddress& srcMacAddr)
        {
            static pcpp::MacAddress dstMacAddr("ff:ff:ff:ff:ff:ff");

            pcpp::EthLayer ethLayer(srcMacAddr, dstMacAddr, PCPP_ETHERTYPE_IP);

            pcpp::Packet packet;
            packet.addLayer(&ethLayer);
            packet.addLayer(ipPacket->ipLayer());
            packet.computeCalculateFields();
            const auto raw = packet.getRawPacket();
            return std::vector<std::uint8_t>(raw->getRawData(), raw->getRawData() + raw->getRawDataLen());
        }
    private:
        EthPacket() = default;
        ~EthPacket() = default;
    };

}