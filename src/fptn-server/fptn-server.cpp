#include <algorithm>
#include <filesystem>

#include <glog/logging.h>
#include <boost/asio.hpp>
#include <argparse/argparse.hpp>

#include <common/data/channel.h>
#include <common/user/manager.h>
#include <common/network/ip_packet.h>
#include <common/network/net_interface.h>
#include <common/jwt_token/token_manager.h>

#include "nat/table.h"
#include "web/server.h"
#include "vpn/manager.h"
#include "filter/manager.h"
#include "system/iptables.h"
#include "network/virtual_interface.h"


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


bool parseBoolean(const std::string& value) {
    std::string lowercasedValue = value;
    std::transform(lowercasedValue.begin(), lowercasedValue.end(), lowercasedValue.begin(), ::tolower);
    return lowercasedValue == "true";
}


int main(int argc, char* argv[]) 
{
    google::InitGoogleLogging(argv[0]);
    google::SetStderrLogging(google::INFO);
    google::SetLogDestination(google::INFO, "");

    if (geteuid() != 0) {
        LOG(ERROR) << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }

    argparse::ArgumentParser args("fptn-server");
    // Required arguments
    args.add_argument("--server-crt")
        .required()
        .help("Path to server.crt file");
    args.add_argument("--server-key")
        .required()
        .help("Path to server.key file");
    args.add_argument("--server-pub")
        .required()
        .help("Path to server.pub file");
    args.add_argument("--out-network-interface")
        .required()
        .help("Network out interface");
    // Optional arguments
    args.add_argument("--server-port")
        .default_value(8080)
        .help("Port number")
        .scan<'i', int>();
    args.add_argument("--tun-interface-name")
        .default_value("tun0")
        .help("Network interface name");
    args.add_argument("--tun-interface-ip")
        .default_value("172.20.0.1")
        .help("IP address of the virtual interface");
    args.add_argument("--tun-interface-network-address")
            .default_value("172.20.0.0")
            .help("IP network of the virtual interface");
    args.add_argument("--tun-interface-network-mask")
        .default_value(24)
        .help("Network mask")
        .scan<'i', int>();
    args.add_argument("--userfile")
        .help("Path to users file (default: /etc/fptn/users.list)")
        .default_value("/etc/fptn/users.list");
    // Packet filters
    args.add_argument("--disable-bittorrent")
        .help("Disable BitTorrent traffic filtering. Use this flag to disable filtering.")
        .default_value("false");
    try {
        args.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        LOG(ERROR) << "Argument parsing error: " << err.what() << std::endl;
        LOG(ERROR) << args;
        return EXIT_FAILURE;
    }

    const auto serverCrt = args.get<std::string>("--server-crt");
    const auto serverKey = args.get<std::string>("--server-key");
    const auto serverPub = args.get<std::string>("--server-key");
    const auto outNetworkInterfaceName = args.get<std::string>("--out-network-interface");
    const auto userFilePath = args.get<std::string>("--userfile");

    const auto serverPort = args.get<int>("--server-port");
    const auto tunInterfaceName = args.get<std::string>("--tun-interface-name");
    const auto tunInterfaceIP = pcpp::IPv4Address(args.get<std::string>("--tun-interface-ip"));
    const auto tunInterfaceNetworkAddress = pcpp::IPv4Address(args.get<std::string>("--tun-interface-network-address"));
    const auto tunInterfaceNetworkMask = args.get<int>("--tun-interface-network-mask");

    auto userManager = std::make_shared<fptn::common::user::UserManager>(
            userFilePath
            );
    auto natTable = std::make_shared<fptn::nat::Table>(
            tunInterfaceIP,
            tunInterfaceNetworkAddress,
            tunInterfaceNetworkMask
            );

    // filters
    const bool disableBittorrent = parseBoolean(args.get<std::string>("--disable-bittorrent"));
    auto filterManager = std::make_shared<fptn::filter::FilterManager>(disableBittorrent);
    
    auto tokenManager = std::make_shared<fptn::common::jwt_token::TokenManager>(
        serverCrt, serverKey, serverPub
    );

    auto iptables = std::make_unique<fptn::system::IPTables>(
        outNetworkInterfaceName, 
        tunInterfaceName
    );

    auto virtualNetworkInterface = std::make_unique<fptn::network::VirtualInterface>(
        tunInterfaceName,
        tunInterfaceIP,
        tunInterfaceNetworkMask, 
        std::move(iptables)
    );

    auto webServer = std::make_unique<fptn::web::Server>(
        natTable,
        serverPort,
        true,
        userManager,
        tokenManager
    );

    fptn::vpn::Manager manager(
        std::move(webServer), 
        std::move(virtualNetworkInterface),
        natTable,
        filterManager
    );

    LOG(INFO) << "Starting server";
    manager.start();

    waitForSignal();

    manager.stop();

    return EXIT_SUCCESS;
}
