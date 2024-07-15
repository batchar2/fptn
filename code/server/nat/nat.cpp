#include "nat.h"


using namespace fptn::nat;


table::table(const pcpp::IPv4Address &vpn_client_network, std::uint32_t vpn_network_mask)
    :
        vpn_client_network_(vpn_client_network),
        vpn_network_mask_(vpn_network_mask),
        network_host_pointer_(0)
{
}

bool table::add_client(const pcpp::IPv4Address &client_ip, const WebSocketChannelPtr& channel, std::uint32_t client_id) noexcept
{
    std::lock_guard<std::mutex> lock(mtx_);
    const std::uint32_t client_ip_int = client_ip.toInt();
    if (fackeip_sessions_.find(client_ip_int) == fackeip_sessions_.end()) {
        // generating the fake address
        // TODO REWRITE!!!!!!
        network_host_pointer_ += 1;
        pcpp::IPv4Address client_fake_ip(std::string("2.2.0.") + std::to_string(network_host_pointer_));  // FOR DEMO TEST
        { // clientid ---> fakeip
            clientid_fackeip.insert({client_id, client_fake_ip.toInt()});
        }
        { // fakeip ---> converter
            auto new_virtual_client_ip = std::make_shared<client_session>(client_ip, client_fake_ip, channel);
            fackeip_sessions_.insert({client_fake_ip.toInt(), std::move(new_virtual_client_ip)});
        }
        return true;
    }
    return false;
}

bool table::del_client(std::uint32_t client_id) noexcept
{
    std::lock_guard<std::mutex> lock(mtx_);
    {
        auto it_clientid_fackeip = clientid_fackeip.find(client_id);
        if (it_clientid_fackeip != clientid_fackeip.end()) {
            const std::uint32_t fackeip = it_clientid_fackeip->second;
            clientid_fackeip.erase(it_clientid_fackeip);
            auto it_fakeip_converter = fackeip_sessions_.find(fackeip);
            if (it_fakeip_converter != fackeip_sessions_.end()) {
                fackeip_sessions_.erase(it_fakeip_converter);
                return true;
            }
        }
    }
    return false;
}

bool table::from_client(pcpp::Packet &packet, std::uint32_t client_id) noexcept
{
    std::lock_guard<std::mutex> lock(mtx_);
    pcpp::IPv4Layer* ip_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ip_layer) {
        auto it_clientid_fackeip = clientid_fackeip.find(client_id);
        if (it_clientid_fackeip != clientid_fackeip.end()) {
            auto it_fakeip_converter = fackeip_sessions_.find(it_clientid_fackeip->second);
            if (it_fakeip_converter != fackeip_sessions_.end()) {
                return it_fakeip_converter->second->from_client(packet);
            }
        }
    }
    return false;
}

WebSocketChannelPtr table::to_client(pcpp::Packet &packet) noexcept
{
    std::lock_guard<std::mutex> lock(mtx_);
    pcpp::IPv4Layer* ip_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ip_layer) {
        const std::uint32_t ip_address_uint = ip_layer->getDstIPv4Address().toInt();
        auto it = fackeip_sessions_.find(ip_address_uint);
        if (it != fackeip_sessions_.end()) {
            if (it->second->to_client(packet)) {
                return it->second->channel();
            }
        }
    }
    // TODO throw exception
    return  WebSocketChannelPtr();
}












