#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#include <boost/asio.hpp>
#include <boost/process.hpp>
#include <argparse/argparse.hpp>

#include <common/logger/logger.h>
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
            spdlog::info("Signal received");
            io_context.stop();
        });
    io_context.run();
}

inline void showVersionAndExit()
{
    std::cerr << "Version: " << FPTN_VERSION << std::endl;
    std::exit(EXIT_SUCCESS);
}

int main(int argc, char* argv[])
{
#if defined(__linux__) || defined(__APPLE__)
    if (geteuid() != 0) {
        std::cerr << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }
#endif
    argparse::ArgumentParser args("fptn-client");
    // Required arguments
    args.add_argument("--access-token")
        .required()
        .help("Access token");
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
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP4)
        .help("Network interface IPv4 address");
    args.add_argument("--tun-interface-ipv6")
        .default_value(FPTN_CLIENT_DEFAULT_ADDRESS_IP6)
        .help("Network interface IPv6 address");
    args.add_argument("--version")
        .help("Show version information");

    try {
        args.parse_args(argc, argv);
        if (args.is_used("--version")) {
            showVersionAndExit();
        }
    } catch (const std::runtime_error& err) {
        if (args.is_used("--version")) {
            showVersionAndExit();
        }
        std::cerr << err.what() << std::endl;
        std::cerr << args;
        return EXIT_FAILURE;
    }

    if (fptn::logger::init("fptn-client-cli")) {
        spdlog::info("Application started successfully.");
    } else {
        std::cerr << "Logger initialization failed. Exiting application." << std::endl;
        return EXIT_FAILURE;
    }

    /* parse cmd args */
    const auto outNetworkInterfaceName = args.get<std::string>("--out-network-interface");
    const auto gatewayIP = pcpp::IPv4Address(args.get<std::string>("--gateway-ip"));
    const auto tunInterfaceName = args.get<std::string>("--tun-interface-name");
    const auto tunInterfaceAddressIPv4 = pcpp::IPv4Address(args.get<std::string>("--tun-interface-ip"));
    const auto tunInterfaceAddressIPv6 = pcpp::IPv6Address(args.get<std::string>("--tun-interface-ipv6"));

    /* check gateway address */
    const auto usingGatewayIP = (
        gatewayIP == pcpp::IPv4Address("0.0.0.0")
        ? fptn::system::getDefaultGatewayIPAddress()
        : pcpp::IPv4Address(gatewayIP)
    );
    if (usingGatewayIP == pcpp::IPv4Address("0.0.0.0")) {
        spdlog::error("Unable to find the default gateway IP address. "
                      "Please check your connection and make sure no other VPN is active. "
                      "If the error persists, specify the gateway address in the FPTN settings using your router's IP "
                      "address with the \"--gateway-ip\" option. If the issue "
                      "remains unresolved, please contact the developer via Telegram @fptn_chat."
        );
        return EXIT_FAILURE;
    }

    /* check config */
    const auto accessToken = args.get<std::string>("--access-token");
    fptn::config::ConfigFile config(accessToken);
    fptn::config::ConfigFile::Server selectedServer;
    try{
        config.parse();
        selectedServer = config.findFastestServer();
    } catch (std::runtime_error &err) {
        spdlog::error("Config error: {}", err.what());
        return EXIT_FAILURE;
    }
    const int serverPort = selectedServer.port;
    const auto serverIP = fptn::system::resolveDomain(selectedServer.host);
    if (serverIP == pcpp::IPv4Address("0.0.0.0")) {
        spdlog::error("DNS resolve error: {}", selectedServer.host);
        return EXIT_FAILURE;
    }

    spdlog::info(
        "VERSION:            {}\n"
        "GATEWAY IP:         {}\n"
        "NETWORK INTERFACE:  {}\n"
        "VPN SERVER NAME:    {}\n"
        "VPN SERVER IP:      {}\n"
        "VPN SERVER PORT:    {}\n"
        "TUN INTERFACE IPv4: {}\n"
        "TUN INTERFACE IPv6: {}\n",
        FPTN_VERSION,
        usingGatewayIP.toString(),
        outNetworkInterfaceName,
        selectedServer.name,
        selectedServer.host,
        selectedServer.port,
        tunInterfaceAddressIPv4.toString(),
        tunInterfaceAddressIPv6.toString()
    );

    /* auth & dns */
    auto webSocketClient = std::make_unique<fptn::http::WebSocketClient>(
        serverIP,
        serverPort,
        tunInterfaceAddressIPv4,
        tunInterfaceAddressIPv6,
        true
    );
    const bool status = webSocketClient->login(config.getUsername(), config.getPassword());
    if (!status) {
        spdlog::error("The username or password you entered is incorrect");
        return EXIT_FAILURE;
    }
    const auto [dnsServerIPv4, dnsServerIPv6] = webSocketClient->getDns();
    if (dnsServerIPv4 == pcpp::IPv4Address("0.0.0.0") || dnsServerIPv6 == pcpp::IPv6Address("")) {
        spdlog::error("DNS server error! Check your connection!");
        return EXIT_FAILURE;
    }

    /* tun interface */
    auto virtualNetworkInterface = std::make_unique<fptn::common::network::TunInterface>(
        tunInterfaceName,
        /* IPv4 */
        tunInterfaceAddressIPv4, 30,
        /* IPv6 */
        tunInterfaceAddressIPv6, 126
    );

    /* iptables */
    auto iptables = std::make_unique<fptn::system::IPTables>(
        outNetworkInterfaceName,
        tunInterfaceName,
        serverIP,
        dnsServerIPv4,
        dnsServerIPv6,
        usingGatewayIP,
        tunInterfaceAddressIPv4,
        tunInterfaceAddressIPv6
    );

    /* vpn client */
    fptn::vpn::VpnClient vpnClient(
        std::move(webSocketClient),
        std::move(virtualNetworkInterface),
        dnsServerIPv4,
        dnsServerIPv6
    );

    /* loop */
    vpnClient.start();
    std::this_thread::sleep_for(std::chrono::seconds(2)); // FIX IT!
    iptables->apply();

    waitForSignal();

    /* clean */
    iptables->clean();
    vpnClient.stop();
    spdlog::shutdown();

    return EXIT_SUCCESS;
}
