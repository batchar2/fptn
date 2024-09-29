#include <filesystem>

#include <glog/logging.h>
#include <boost/asio.hpp>

#include <common/data/channel.h>

#include <common/network/ip_packet.h>
#include <common/network/net_interface.h>
#include <common/jwt_token/token_manager.h>

#include "nat/table.h"
#include "web/server.h"
#include "vpn/manager.h"
#include "cmd/cmd_option.h"
#include "filter/manager.h"
#include "system/iptables.h"
#include "statistic/metrics.h"
#include "user/user_manager.h"
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

    /* Check options */
    auto options = std::make_shared<fptn::cmd::CmdOptions>(argc, argv);
    if(!options->parse()) {
        return EXIT_FAILURE;
    }
    if (!std::filesystem::exists(options->getServerCrt())
        || !std::filesystem::exists(options->getServerKey())
        || !std::filesystem::exists(options->getServerPub())
    ) {
        LOG(ERROR) << "SSL certificate or key file does not exist!";
        return EXIT_FAILURE;
    }

    /* Init virtual network interface */
    auto iptables = std::make_unique<fptn::system::IPTables>(
        options->getOutNetworkInterface(),
        options->getTunInterfaceName()
    );
    auto virtualNetworkInterface = std::make_unique<fptn::network::VirtualInterface>(
        options->getTunInterfaceName(),
        options->getTunInterfaceIP(),
        options->getTunInterfaceNetworkMask(),
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
        options->getTunInterfaceIP(),
        options->getTunInterfaceNetworkAddress(),
        options->getTunInterfaceNetworkMask()
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
        options->getTunInterfaceIP()
    );

    /* init vpn manager */
    auto filterManager = std::make_shared<fptn::filter::FilterManager>(options->disableBittorrent());
    fptn::vpn::Manager manager(
        std::move(webServer),
        std::move(virtualNetworkInterface),
        natTable,
        filterManager,
        prometheus
    );

    LOG(INFO) << std::endl
        << "Starting server"     << std::endl
        << "VERSION:           " << FPTN_VERSION << std::endl
        << "NETWORK INTERFACE: " << options->getOutNetworkInterface() << std::endl
        << "VPN SERVER IP:     " << options->getTunInterfaceIP().toString() << std::endl
        << "VPN SERVER PORT:   " << options->getServerPort() << std::endl
        << std::endl;

    /* start/wait/stop */
    manager.start();
    waitForSignal();
    manager.stop();
    google::ShutdownGoogleLogging();

    return EXIT_SUCCESS;
}
