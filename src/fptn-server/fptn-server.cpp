#include <filesystem>

#include <boost/asio.hpp>

#include <common/data/channel.h>
#include <common/logger/logger.h>
#include <common/network/ip_packet.h>
#include <common/network/net_interface.h>
#include <common/jwt_token/token_manager.h>

#include "nat/table.h"
#include "web/server.h"
#include "vpn/manager.h"
#include "cmd/cmd_option.h"
#include "system/iptables.h"
#include "statistic/metrics.h"
#include "user/user_manager.h"
#include "network/virtual_interface.h"

#include "filter/manager.h"
#include "filter/packets/antiscan/antiscan.h"
#include "filter/packets/bittorrent/bittorrent.h"


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


int main(int argc, char* argv[]) 
{
#if defined(__linux__) || defined(__APPLE__)
    if (geteuid() != 0) {
        std::cerr << "You must be root to run this program." << std::endl;
        return EXIT_FAILURE;
    }
#endif
    if (fptn::logger::init("fptn-server")) {
        spdlog::info("Application started successfully.");
    } else {
        std::cerr << "Logger initialization failed. Exiting application." << std::endl;
        return EXIT_FAILURE;
    }

    /* Check options */
    auto options = std::make_shared<fptn::cmd::CmdOptions>(argc, argv);
    if(!options->parse()) {
        return EXIT_FAILURE;
    }
    if (!std::filesystem::exists(options->getServerCrt())
        || !std::filesystem::exists(options->getServerKey())
        || !std::filesystem::exists(options->getServerPub())
    ) {
        spdlog::error("SSL certificate or key file does not exist!");
        return EXIT_FAILURE;
    }

    /* Init virtual network interface */
    auto iptables = std::make_unique<fptn::system::IPTables>(
        options->getOutNetworkInterface(),
        options->getTunInterfaceName()
    );

    auto virtualNetworkInterface = std::make_unique<fptn::network::VirtualInterface>(
        options->getTunInterfaceName(),
        /* IPv+4 */
        options->getTunInterfaceIPv4(),
        options->getTunInterfaceNetworkIPv4Mask(),
        /* IPv6 */
        options->getTunInterfaceIPv6(),
        options->getTunInterfaceNetworkIPv6Mask(),
        /* iptables */
        std::move(iptables)
    );

    /* Init web server */
    auto tokenManager = std::make_shared<fptn::common::jwt_token::TokenManager>(
        options->getServerCrt(), options->getServerKey(), options->getServerPub()
    );
    auto userManager = std::make_shared<fptn::user::UserManager>(
        options->getUserFile(),
        options->useRemoteServerAuth(),
        options->getRemoteServerAuthHost(),
        options->getRemoteServerAuthPort()
    );
    auto natTable = std::make_shared<fptn::nat::Table>(
        /* IPv4 */
        options->getTunInterfaceIPv4(),
        options->getTunInterfaceNetworkIPv4Address(),
        options->getTunInterfaceNetworkIPv4Mask(),
        /* IPv6 */
        options->getTunInterfaceIPv6(),
        options->getTunInterfaceNetworkIPv6Address(),
        options->getTunInterfaceNetworkIPv6Mask()
    );
    auto prometheus = std::make_shared<fptn::statistic::Metrics>();
    auto webServer = std::make_unique<fptn::web::Server>(
        natTable,
        options->getServerPort(),
        options->useHttps(),
        userManager,
        tokenManager,
        prometheus,
        options->getPrometheusAccessKey(),
        options->getTunInterfaceIPv4(),
        options->getTunInterfaceIPv6()
    );

    /* init packet filter */
    auto filterManager = std::make_shared<fptn::filter::FilterManager>();
    if (options->disableBittorrent()) { // block bittorrent traffic
        filterManager->add(std::make_shared<fptn::filter::packets::BitTorrentFilter>());
    }
    filterManager->add( // Prevent sending requests to the VPN virtual network from the client
        std::make_shared<fptn::filter::packets::AntiScanFilter>(
            /* IPv4 */
            options->getTunInterfaceIPv4(),
            options->getTunInterfaceNetworkIPv4Address(),
            options->getTunInterfaceNetworkIPv4Mask(),
            /* IPv6 */
            options->getTunInterfaceIPv6(),
            options->getTunInterfaceNetworkIPv6Address(),
            options->getTunInterfaceNetworkIPv6Mask()
        )
    );

    /* init vpn manager */
    fptn::vpn::Manager manager(
        std::move(webServer),
        std::move(virtualNetworkInterface),
        natTable,
        filterManager,
        prometheus
    );

    spdlog::info("\n--- Starting server---\n"
        "VERSION:           {}\n"
        "NETWORK INTERFACE: {}\n"
        "VPN NETWORK IPv4:  {}\n"
        "VPN NETWORK IPv6:  {}\n"
        "VPN SERVER PORT:   {}\n",
        FPTN_VERSION,
        options->getOutNetworkInterface(),
        options->getTunInterfaceNetworkIPv4Address().toString(),
        options->getTunInterfaceNetworkIPv6Address().toString(),
        options->getServerPort()
    );

    /* start/wait/stop */
    manager.start();
    waitForSignal();
    manager.stop();
    spdlog::shutdown();

    return EXIT_SUCCESS;
}
