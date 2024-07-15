#include "client_session.h"

using namespace fptn::nat;


client_session::client_session(
    const pcpp::IPv4Address &client_real_ip,
    const pcpp::IPv4Address &client_vpn_ip,
    const WebSocketChannelPtr& ch
)
    :
        client_real_ip_(client_real_ip),
        client_vpn_ip_(client_vpn_ip),
        channel_(ch),
        last_update_(std::chrono::steady_clock::now())
{
}

bool client_session::from_client(pcpp::Packet &packet) noexcept
{
    pcpp::IPv4Layer* ip_v4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ip_v4_layer) {
        ip_v4_layer->getIPv4Header()->timeToLive -= 1;
        ip_v4_layer->setSrcIPv4Address(client_vpn_ip_);
        ip_v4_layer->computeCalculateFields();
        {  // tcp
            pcpp::TcpLayer* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>();
            if (tcp_layer) {
                tcp_layer->computeCalculateFields();
            }
        }
        last_update_ = std::chrono::steady_clock::now();
        return true;
    }
    return false;
}

const WebSocketChannelPtr client_session::channel() noexcept
{
    return channel_;
}


bool client_session::to_client(pcpp::Packet &packet) noexcept
{
    pcpp::IPv4Layer* ip_v4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ip_v4_layer) {
        ip_v4_layer->getIPv4Header()->timeToLive -= 1;
        ip_v4_layer->setDstIPv4Address(client_real_ip_);
        ip_v4_layer->computeCalculateFields();
        {  // tcp
            pcpp::TcpLayer* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>();
            if (tcp_layer) {
                tcp_layer->computeCalculateFields();
            }
        }

        last_update_ = std::chrono::steady_clock::now();
        return true;
    }
    return false;
}
