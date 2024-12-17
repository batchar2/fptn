#pragma once

#include <memory>

#include <common/network/ip_packet.h>


namespace fptn::filter::packets
{

    using namespace fptn::common::network;

    class BaseFilter 
    {
    public:
        BaseFilter() = default;
        virtual IPPacketPtr apply(IPPacketPtr packet) const noexcept = 0;
        ~BaseFilter() = default;
    };

    using BaseFilterSPtr = std::shared_ptr<BaseFilter>;
}
