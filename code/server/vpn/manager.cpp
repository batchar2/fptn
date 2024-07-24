#include "manager.h"

using namespace fptn::vpn;


Manager::Manager(
    fptn::web::ServerSPtr webServer, 
    fptn::network::VirtualInterfaceSPtr networkInterface,
    fptn::nat::TableSPtr nat
)
:
    webServer_(std::move(webServer)),
    networkInterface_(std::move(networkInterface)),
    nat_(std::move(nat))
{
}


Manager::~Manager()
{
    stop();
}


bool Manager::stop() noexcept
{
    running_ = false;
    if (readToClientThread_.joinable()) {
        readToClientThread_.join();
    }
    if (readFromClientThread_.joinable()) {
        readFromClientThread_.join();
    }
    return (networkInterface_->stop() && webServer_->stop());
}


bool Manager::start() noexcept
{
    running_ = true;
    webServer_->start();
    networkInterface_->start();

    readToClientThread_ = std::thread(&Manager::runToClient, this);
    bool toStatus = readToClientThread_.joinable();

    readFromClientThread_ = std::thread(&Manager::runFromClient, this);
    bool fromStatus = readFromClientThread_.joinable();

    return (toStatus && fromStatus);
}


void Manager::runToClient() noexcept
{
    const std::chrono::milliseconds timeout{300};
    while (running_) {
        auto packet = networkInterface_->waitForPacket(timeout);
        if (!packet) {
            continue;
        }
        auto session = nat_->getSessionByFakeIP(packet->ipLayer()->getDstIPv4Address());
        if (!session) {
            continue;
        }
        auto shaper = session->getTrafficShaper();
        if (shaper == nullptr || (shaper != nullptr && shaper->checkSpeedLimit(packet->size()))) {
            webServer_->send(
                session->changeIPAddressToCleintIP(std::move(packet))
            );
        }
    }
}


void Manager::runFromClient() noexcept
{
    const std::chrono::milliseconds timeout{300};
    while (running_) {
        auto packet = webServer_->waitForPacket(timeout);
        if (!packet) {
            continue;
        }
        auto session = nat_->getSessionByClientId(packet->clientId());
        if (!session) {
            continue;
        }
        auto shaper = session->getTrafficShaper();
        if (shaper == nullptr || (shaper != nullptr && shaper->checkSpeedLimit(packet->size()))) {
            networkInterface_->send(
                session->changeIPAddressToFakeIP(std::move(packet))
            );
        }
    }
}
