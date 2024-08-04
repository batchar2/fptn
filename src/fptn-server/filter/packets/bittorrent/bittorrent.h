#pragma once

#include <filter/packets/base.h>


namespace fptn::filter::packets
{

    using namespace fptn::common::network;

    class BitTorrentFilter : public BaseFilter
    {
    public:
        BitTorrentFilter();
        virtual IPPacketPtr apply(IPPacketPtr packet) noexcept override;
        virtual ~BitTorrentFilter() = default;
    };
}
