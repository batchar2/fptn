#include <regex>
#include <iostream>

#include <boost/asio.hpp>
#include <argparse/argparse.hpp>

#include <common/data/channel.h>
#include <common/network/ip_packet.h>
#include <common/network/tun_interface.h>

#include "vpn/vpn_client.h"
#include "system/iptables.h"
#include "http/websocket_client.h"


inline void waitForSignal() 
{
    boost::asio::io_context io_context;
    boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait(
        [&](auto, auto) {
            LOG(INFO) << "Signal received";
            io_context.stop();
        });
    io_context.run();
}

std::string extractIpOrHost(const std::string& url) {
    std::regex rgx(R"(^(wss://)([a-zA-Z0-9.-]+)(:\d+)?/.*$)");
    std::smatch match;

    if (std::regex_search(url, match, rgx)) {
        return match[2];
    }
    return ""; 
}



int main(int argc, char* argv[])
{
    google::InitGoogleLogging(argv[0]);
    google::SetStderrLogging(google::INFO);
    google::SetLogDestination(google::INFO, "");

    argparse::ArgumentParser program_args("fptn-client");
    // Required arguments
    program_args.add_argument("--vpn-server-uri")
        .required()
        .help("Host address");
    program_args.add_argument("--out-network-interface")
        .required()
        .help("Network out interface");
    // Optional arguments
    program_args.add_argument("--gateway-ip")
        .default_value("")
        .help("Your default gateway ip");
    program_args.add_argument("--tun-interface-name")
        .default_value("tun0")
        .help("Network interface name");
    program_args.add_argument("--tun-interface-address")
        .default_value("10.10.10.1")
        .help("Network interface address");    
    try {
        program_args.parse_args(argc, argv);
    } catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program_args;
        return EXIT_FAILURE;
    }

    const auto vpnServerURL = program_args.get<std::string>("--vpn-server-uri");
    const auto outNetworkInterfaceName = program_args.get<std::string>("--out-network-interface");

    const auto gatewayIP = program_args.get<std::string>("--gateway-ip");    
    const auto tunInterfaceName = program_args.get<std::string>("--tun-interface-name");
    const auto tunInterfaceAddress = program_args.get<std::string>("--tun-interface-address"); 
   
    const std::string vpnServerIP = extractIpOrHost(vpnServerURL);


    auto iptables = std::make_unique<fptn::system::IPTables>(
        outNetworkInterfaceName,
        tunInterfaceName,
        vpnServerIP,
        gatewayIP
    );

    auto webSocketClient = std::make_unique<fptn::http::WebSocketClient>(
        vpnServerURL,
        "token",
        tunInterfaceAddress,
        true
    );

    auto virtualNetworkInterface = std::make_unique<fptn::common::network::TunInterface>(
        tunInterfaceName, tunInterfaceAddress, 30, nullptr
    );

    fptn::vpn::VpnClient vpnClient(
        std::move(webSocketClient),
        std::move(virtualNetworkInterface)
    );


    vpnClient.start();

    std::this_thread::sleep_for(std::chrono::seconds(1)); // FIX IT!

    iptables->apply();

    waitForSignal();
    
    vpnClient.stop();

    google::ShutdownGoogleLogging();


    return EXIT_SUCCESS;
}