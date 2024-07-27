#include <filesystem>

#include <glog/logging.h>
#include <boost/asio.hpp>
#include <argparse/argparse.hpp>

#include <common/data/channel.h>
#include <common/user/manager.h>
#include <common/network/ip_packet.h>
#include <common/network/tun_interface.h>
#include <common/jwt_token/token_manager.h>

#include "nat/table.h"
#include "web/server.h"
#include "vpn/manager.h"
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


int main(int argc, char* argv[]) 
{
    google::InitGoogleLogging(argv[0]);
    google::SetStderrLogging(google::INFO);
    google::SetLogDestination(google::INFO, "");

    if (geteuid() != 0) {
        LOG(ERROR) << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }

    argparse::ArgumentParser program_args("fptn-server");
    // Required arguments
    program_args.add_argument("--server-crt")
        .required()
        .help("Path to server.crt file");
    program_args.add_argument("--server-key")
        .required()
        .help("Path to server.key file");
    program_args.add_argument("--server-pub")
        .required()
        .help("Path to server.pub file");
    program_args.add_argument("--out-network-interface")
        .required()
        .help("Network out interface");
    // Optional arguments
    program_args.add_argument("--server-port")
        .default_value(8080)
        .help("Port number")
        .scan<'i', int>();
    program_args.add_argument("--tun-interface-name")
        .default_value("tun0")
        .help("Network interface name");
    program_args.add_argument("--tun-interface-address")
        .default_value("2.2.0.1")
        .help("IP address of the virtual interface");
    program_args.add_argument("--tun-interface-network-mask")
        .default_value(24)
        .help("Network mask")
        .scan<'i', int>();
    program_args.add_argument("--userfile")
        .help("Path to users file (default: /etc/fptn/users.list)")
        .default_value("/etc/fptn/users.list");

    try {
        program_args.parse_args(argc, argv);
    } catch (const std::logic_error& err) {
        LOG(ERROR) << "Argument parsing error: " << err.what() << std::endl;
        LOG(ERROR) << program_args;
        return EXIT_FAILURE;
    }

    const auto serverCrt = program_args.get<std::string>("--server-crt");
    const auto serverKey = program_args.get<std::string>("--server-key");
    const auto serverPub = program_args.get<std::string>("--server-key");
    const auto outNetworkInterfaceName = program_args.get<std::string>("--out-network-interface");
    const auto userFilePath = program_args.get<std::string>("--userfile");

    const auto serverPort = program_args.get<int>("--server-port");

    const auto tunInterfaceName = program_args.get<std::string>("--tun-interface-name");
    const auto tunInterfaceAddress = program_args.get<std::string>("--tun-interface-address");
    const auto tunInterfaceNetworkMask = program_args.get<int>("--tun-interface-network-mask");

    auto userManager = std::make_shared<fptn::common::user::UserManager>(userFilePath);
    auto natTable = std::make_shared<fptn::nat::Table>(tunInterfaceAddress, tunInterfaceNetworkMask);

    auto tokenManager = std::make_shared<fptn::common::jwt_token::TokenManager>(
        serverCrt, serverKey, serverPub
    );

    auto iptables = std::make_unique<fptn::system::IPTables>(
        outNetworkInterfaceName, 
        tunInterfaceName
    );

    auto virtualNetworkInterface = std::make_unique<fptn::network::VirtualInterface>(
        tunInterfaceName, 
        tunInterfaceAddress, 
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
        natTable
    );

    LOG(INFO) << "Starting server";
    manager.start();

    waitForSignal();

    manager.stop();

    return EXIT_SUCCESS;
}
