#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include <glog/logging.h>

#include <boost/asio.hpp>
#include <boost/process.hpp>
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


int main(int argc, char* argv[])
{
#if defined(__linux__) || defined(__APPLE__)
    if (geteuid() != 0) {
        std::cerr << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }
#endif
    google::InitGoogleLogging(argv[0]);
    google::SetStderrLogging(google::INFO);
    google::SetLogDestination(google::INFO, "");

    argparse::ArgumentParser args("fptn-client");
    // Required arguments
    args.add_argument("--vpn-server-ip")
        .required()
        .help("Host address");
    args.add_argument("--vpn-server-port")
        .default_value(8080)
        .help("Port number")
        .scan<'i', int>();
    args.add_argument("--out-network-interface")
        .required()
        .help("Network out interface");
    args.add_argument("--username")
        .required()
        .help("Username");
    args.add_argument("--password")
        .required()
        .help("Username");
    // Optional arguments
    args.add_argument("--gateway-ip")
        .default_value("")
        .help("Your default gateway ip");
    args.add_argument("--tun-interface-name")
        .default_value("tun0")
        .help("Network interface name");
    args.add_argument("--tun-interface-ip")
        .default_value("10.10.10.1")
        .help("Network interface address");    
    try {
        args.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << args;
        return EXIT_FAILURE;
    }

    const auto vpnServerIP = args.get<std::string>("--vpn-server-ip");
    const auto vpnServerPort = args.get<int>("--vpn-server-port");
    const auto outNetworkInterfaceName = args.get<std::string>("--out-network-interface");

    const auto username = args.get<std::string>("--username");
    const auto password = args.get<std::string>("--password");

    const auto gatewayIP = args.get<std::string>("--gateway-ip");    
    const auto tunInterfaceName = args.get<std::string>("--tun-interface-name");
    const auto tunInterfaceAddress = args.get<std::string>("--tun-interface-ip");

    const std::string usingGatewayIP = (!gatewayIP.empty() ? gatewayIP : fptn::system::getDefaultGatewayIPAddress());
    if (usingGatewayIP.empty()) {
        LOG(ERROR) << "Error: Unable to find the default gateway IP address. Please specify it using the \"--gateway-ip\" option." << std::endl;
        return EXIT_FAILURE;
    }
    LOG(INFO) << std::endl
        << "GATEWAY IP:        " << usingGatewayIP << std::endl
        << "NETWORK INTERFACE: " << outNetworkInterfaceName << std::endl
        << "VPN SERVER IP:     " << vpnServerIP << std::endl
        << "VPN SERVER PORT:   " << vpnServerPort << std::endl
        << std::endl;


    auto webSocketClient = std::make_unique<fptn::http::WebSocketClient>(
        vpnServerIP, 
        vpnServerPort,
        tunInterfaceAddress,
        true
    );

    bool status = webSocketClient->login(username, password);
    if (!status) {
        LOG(ERROR) << "The username or password you entered is incorrect" << std::endl;
        return EXIT_FAILURE;
    }

    auto iptables = std::make_unique<fptn::system::IPTables>(
        outNetworkInterfaceName,
        tunInterfaceName,
        vpnServerIP,
        usingGatewayIP
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