#include "manager.h"

#include "packets/bittorrent/bittorrent.h"


using namespace fptn::filter;

void FilterManager::add(packets::BaseFilterSPtr filter) noexcept
{
    filters_.push_back(std::move(filter));
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
