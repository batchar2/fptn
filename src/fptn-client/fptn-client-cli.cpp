#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include <glog/logging.h>

#include <boost/asio.hpp>
#include <boost/process.hpp>
#include <argparse/argparse.hpp>

#include <common/network/net_interface.h>

#include "vpn/vpn_client.h"
#include "system/iptables.h"
#include "config/config_file.h"
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
    google::SetStderrLogging(google::GLOG_INFO);
    google::SetLogDestination(google::GLOG_INFO, "");

    argparse::ArgumentParser args("fptn-client");
    // Required arguments
    args.add_argument("--access-config")
        .required()
        .help("Config path");
    // Optional arguments
    args.add_argument("--out-network-interface")
        .default_value("")
        .help("Network out interface");
    args.add_argument("--gateway-ip")
        .default_value("0.0.0.0")
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
    /* parse cmd args */
    const auto outNetworkInterfaceName = args.get<std::string>("--out-network-interface");
    const auto gatewayIP = pcpp::IPv4Address(args.get<std::string>("--gateway-ip"));
    const auto tunInterfaceName = args.get<std::string>("--tun-interface-name");
    const auto tunInterfaceAddress = pcpp::IPv4Address(args.get<std::string>("--tun-interface-ip"));

    /* check gateway address */
    const auto usingGatewayIP = (
        gatewayIP == pcpp::IPv4Address("0.0.0.0")
        ? fptn::system::getDefaultGatewayIPAddress()
        : pcpp::IPv4Address(gatewayIP)
    );
    if (usingGatewayIP == pcpp::IPv4Address("0.0.0.0")) {
        LOG(ERROR) << "Error: Unable to find the default gateway IP address. Please specify it using the \"--gateway-ip\" option." << std::endl;
        return EXIT_FAILURE;
    }

    /* check config */
    const std::filesystem::path configPath = args.get<std::string>("--access-config");
    if (!std::filesystem::exists(configPath)) {
        LOG(ERROR) << "Config file '"  << configPath << "' not found!";
        return EXIT_FAILURE;
    }
    fptn::config::ConfigFile config(configPath);
    fptn::config::ConfigFile::Server selectedServer;
    try{
        config.parse();
        selectedServer = config.findFastestServer();
    } catch (std::runtime_error &err) {
        LOG(ERROR) << "Config error: " << err.what();
        return EXIT_FAILURE;
    }
    const int serverPort = selectedServer.port;
    const auto serverIP = fptn::system::resolveDomain(selectedServer.host);
    if (serverIP == pcpp::IPv4Address("0.0.0.0")) {
        LOG(ERROR) << "DNS resolve error: " << selectedServer.host;
        return EXIT_FAILURE;
    }

    /* auth & dns */
    auto webSocketClient = std::make_unique<fptn::http::WebSocketClient>(
        serverIP,
        serverPort,
        tunInterfaceAddress,
        true
    );
    const bool status = webSocketClient->login(config.getUsername(), config.getPassword());
    if (!status) {
        LOG(ERROR) << "The username or password you entered is incorrect" << std::endl;
        return EXIT_FAILURE;
    }
    const auto dnsServer = webSocketClient->getDns();
    if (dnsServer == pcpp::IPv4Address("0.0.0.0")) {
        LOG(ERROR) << "DNS server error! Check your connection!" << std::endl;
        return EXIT_FAILURE;
    }

    /* tun interface */
    auto virtualNetworkInterface = std::make_unique<fptn::common::network::TunInterface>(
        tunInterfaceName, tunInterfaceAddress, 30
    );

    /* iptables */
    auto iptables = std::make_unique<fptn::system::IPTables>(
        outNetworkInterfaceName,
        tunInterfaceName,
        serverIP,
        dnsServer,
        usingGatewayIP,
        tunInterfaceAddress
    );

    /* vpn client */
    fptn::vpn::VpnClient vpnClient(
        std::move(webSocketClient),
        std::move(virtualNetworkInterface),
        dnsServer
    );

    /* loop */
    LOG(INFO) << std::endl
        << "VERSION:           " << FPTN_VERSION << std::endl
        << "GATEWAY IP:        " << usingGatewayIP << std::endl
        << "NETWORK INTERFACE: " << outNetworkInterfaceName << std::endl
        << "VPN SERVER NAME:   " << selectedServer.name << std::endl
        << "VPN SERVER IP:     " << selectedServer.host << std::endl
        << "VPN SERVER PORT:   " << selectedServer.port << std::endl
        << "TUN INTERFACE IP:  " << tunInterfaceAddress.toString() << std::endl;

    vpnClient.start();
    std::this_thread::sleep_for(std::chrono::seconds(2)); // FIX IT!
    iptables->apply();

    waitForSignal();

    /* clean */
    iptables->clean();
    vpnClient.stop();
    google::ShutdownGoogleLogging();

    return EXIT_SUCCESS;
}
