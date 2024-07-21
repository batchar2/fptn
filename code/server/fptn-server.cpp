#include <iostream>
#include <filesystem>

#include <boost/asio.hpp>
#include <argparse/argparse.hpp>

#include <network/tun_interface.h>

#include "nat/nat.h"
#include "web/server.h"


inline void wait_for_signal()
{
    boost::asio::io_context io_context;
    boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait(
        [&](auto, auto) {
            std::clog << "Signal received" << std::endl;
            io_context.stop();
        });
    io_context.run();
}


int main(int argc, char* argv[])
{
    google::InitGoogleLogging(argv[0]);

    argparse::ArgumentParser program_args("fptn-server");
    program_args.add_argument("-p", "--server-port")
        .default_value(8080)
        .help("Port number")
        .scan<'i', int>();
    program_args.add_argument("--server-address")
        .default_value("0.0.0.0")
        .help("Host address");
    program_args.add_argument("--interface-address")
        .default_value("1.1.1.1")
        .help("Interface address");
    program_args.add_argument("--interface-network-mask")
        .default_value(24)
        .help("Network mask")
        .scan<'i', int>();
    program_args.add_argument("--interface-name")
        .required()
        .help("Network interface name");
    program_args.add_argument("--server-crt")
        .required()
        .help("Path to server.crt file");
    program_args.add_argument("--server-key")
        .required()
        .help("Path to server.key file");

    try {
        program_args.parse_args(argc, argv);
    } catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program_args;
        return EXIT_FAILURE;
    }

    const int port = program_args.get<int>("--server-port");
    const std::string server_address = program_args.get<std::string>("--server-address");

    const int network_mask = program_args.get<int>("--interface-network-mask");
    const std::string interface_name = program_args.get<std::string>("--interface-name");
    const std::string interface_address = program_args.get<std::string>("--interface-address");

    const std::filesystem::path server_crt = program_args.get<std::string>("--server-crt");
    const std::filesystem::path server_key = program_args.get<std::string>("--server-key");

    auto nat_table = std::make_shared<fptn::nat::table>(
        pcpp::IPv4Address("2.2.0.0"),
        16
    );

    auto websocket_server = std::make_shared<fptn::web::server>(
        port,
        true,
        server_crt,
        server_key,
        [nat_table](const WebSocketChannelPtr& channel, const std::string& client_ip, const std::uint32_t client_id) -> void 
        {
            // new connection
            std::cerr << "new connection> " << client_ip << "--" << client_id << std::endl;
            const pcpp::IPv4Address client_address(client_ip);
            nat_table->add_client(client_address, channel, client_id);
        },
        [nat_table](const WebSocketChannelPtr& channel, const std::uint32_t client_id) -> void 
        {
            nat_table->del_client(client_id);
            (void)channel;
        });

    auto net_interface = std::make_shared<fptn::network::tun_interface>(
        interface_name,
        interface_address,
        24
    );

    net_interface->start(
        [net_interface, websocket_server, nat_table](const std::string& raw_ip_packet_data) -> void
        {
            pcpp::RawPacket raw_packet(
                (const std::uint8_t*)raw_ip_packet_data.c_str(),
                (int)raw_ip_packet_data.size(),
                timeval { 0, 0 },
                false,
                pcpp::LINKTYPE_IPV4
            );
            pcpp::Packet parsed_packet(&raw_packet, false);
            if (parsed_packet.isPacketOfType(pcpp::IPv4) || parsed_packet.isPacketOfType(pcpp::IP)) {
                const pcpp::IPv4Layer* ip_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
                if (ip_layer) {
                    auto channel = nat_table->to_client(parsed_packet);
                    if (channel != nullptr) {
                        const auto raw_repl_packet = parsed_packet.getRawPacket();
                        channel->send((char*)raw_repl_packet->getRawData(), raw_repl_packet->getRawDataLen());
                    }
                }
            }
        }
    );

    websocket_server->start(
        [net_interface, nat_table](const std::string& raw_ip_packet_data, const std::uint32_t client_id) -> void
        {
            pcpp::RawPacket raw_packet(
                (const std::uint8_t*)raw_ip_packet_data.c_str(),
                (int)raw_ip_packet_data.size(),
                timeval { 0, 0 },
                false,
                pcpp::LINKTYPE_IPV4
            );
            pcpp::Packet parsed_packet(&raw_packet, false);
            if (parsed_packet.isPacketOfType(pcpp::IPv4) || parsed_packet.isPacketOfType(pcpp::IP)) {
                const pcpp::IPv4Layer* ip_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
                if (ip_layer && nat_table->from_client(parsed_packet, client_id)) {
                    const auto raw_repl_packet = parsed_packet.getRawPacket();
                    net_interface->send((void*)raw_repl_packet->getRawData(), raw_repl_packet->getRawDataLen());
                }
            }
        }
    );

    {
        wait_for_signal();
    }

    net_interface->stop();
    websocket_server->stop();

    google::ShutdownGoogleLogging();

    return EXIT_SUCCESS;
}
