#include <iostream>

#include <boost/asio.hpp>
#include <argparse/argparse.hpp>

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>

#include <network/tun_interface.h>

#include "websocket/client.h"


inline void wait_for_signal()
{
    boost::asio::io_context io_context;
    boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait(
        [&](auto, auto) {
            std::clog << "Signal received" << std::endl;
            io_context.stop();
        }
    );
    io_context.run();
}


int main(int argc, char* argv[])
{
    google::InitGoogleLogging(argv[0]);

    argparse::ArgumentParser program_args("fptn-client");
    program_args.add_argument("--interface-name")
        .required()
        .help("Network interface name");
    program_args.add_argument("--server-uri")
        .required()
        .help("Host address");
    program_args.add_argument("--interface-address")
        .default_value("10.10.10.1")
        .help("Network interface address");
    program_args.add_argument("--interface-network-mask")
        .default_value(24)
        .help("Network mask")
        .scan<'i', int>();
    try {
        program_args.parse_args(argc, argv);
    } catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program_args;
        return EXIT_FAILURE;
    }

    const std::string server_uri = program_args.get<std::string>("--server-uri");

    const int interface_network_mask = program_args.get<int>("--interface-network-mask");
    const std::string interface_name = program_args.get<std::string>("--interface-name");
    const std::string interface_address = program_args.get<std::string>("--interface-address"); 

    auto websocket_client = std::make_shared<fptn::websocket::client>(
        server_uri,
        "token",
        interface_address,
        true
    );
    auto net_interface = std::make_shared<fptn::network::tun_interface>(
        interface_name,    
        interface_address,
        interface_network_mask
    );
    net_interface->start(
        [websocket_client](const std::string& raw_ip_packet_data) -> void
        {
            pcpp::RawPacket raw_packet(
                (const std::uint8_t*)raw_ip_packet_data.c_str(),
                (int)raw_ip_packet_data.size(),
                timeval{0, 0}, 
                false, 
                pcpp::LINKTYPE_IPV4
            );
            pcpp::Packet parsed_packet(&raw_packet, false);
            if (parsed_packet.isPacketOfType(pcpp::IPv4) || parsed_packet.isPacketOfType(pcpp::IP)) {
                const pcpp::IPv4Layer* ip_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
                if (ip_layer) {
                    websocket_client->send(raw_ip_packet_data);
                    std::cerr << "send to websocket>" << std::endl;
                }
            }   
        }
    );
    websocket_client->start(
        [net_interface](const std::string& raw_ip_packet_data) -> void
        {
            pcpp::RawPacket raw_packet(
                (const std::uint8_t*)raw_ip_packet_data.c_str(),
                (int)raw_ip_packet_data.size(),
                timeval{0, 0}, 
                false, 
                pcpp::LINKTYPE_IPV4
            );
            pcpp::Packet parsed_packet(&raw_packet, false);
            if (parsed_packet.isPacketOfType(pcpp::IPv4) || parsed_packet.isPacketOfType(pcpp::IP)) {
                const pcpp::IPv4Layer* ip_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
                if (ip_layer) {
                    net_interface->send(raw_ip_packet_data);
                    std::cerr << "send to network>" << std::endl;
                }
            }
        }
    );
    
    // main loop
    wait_for_signal();
    
    
    net_interface->stop();
    websocket_client->stop();

    google::ShutdownGoogleLogging();

    return EXIT_SUCCESS;
}