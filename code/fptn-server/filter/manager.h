#pragma once

#include <vector>
#include <memory>

#include <common/network/ip_packet.h>

#include "packets/base.h"


namespace fptn::filter
{

    using namespace fptn::common::network;

    class FilterManager 
    {
    public:
        FilterManager(bool disableBittorrent=false);
        IPPacketPtr apply(IPPacketPtr packet) const;
    private:
        std::vector<packets::BaseFilterSPtr> filters_;
    };

    using FilterManagerSPtr = std::shared_ptr<FilterManager>;
}
