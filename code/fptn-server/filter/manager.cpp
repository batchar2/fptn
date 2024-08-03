#include "manager.h"

#include "packets/bittorrent/bittorrent.h"


using namespace fptn::filter;


FilterManager::FilterManager(bool bittorent)
{
    if (bittorent) {
        filters_.push_back(std::make_shared<packets::BitTorrentFilter>());
    }
}

IPPacketPtr FilterManager::apply(IPPacketPtr packet) const 
{
    for (const auto& filter : filters_) {
        packet = filter->apply(std::move(packet));
        if (!packet) {
            return nullptr; // packet was filtered
        }
    }
    return packet;
}
