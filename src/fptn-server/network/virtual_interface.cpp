#include "virtual_interface.h"

using namespace fptn::network;


VirtualInterface::VirtualInterface(
    const std::string &name,
    const pcpp::IPv4Address& ipv4Address,
    const int ipv4Netmask,
    const pcpp::IPv6Address& ipv6Address,
    const int ipv6Netmask,
    fptn::system::IPTablesPtr iptables
)
    : iptables_(std::move(iptables))
{
    auto callback = std::bind(&VirtualInterface::newIPPacketFromNetwork, this, std::placeholders::_1);
    virtualNetworkInterface_ = std::make_unique<fptn::common::network::TunInterface>(
        name, ipv4Address, ipv4Netmask, ipv6Address, ipv6Netmask, callback
    );
}

VirtualInterface::~VirtualInterface()
{
    stop();
}

bool VirtualInterface::check() noexcept
{
    return true;
}

bool VirtualInterface::start() noexcept
{
    running_ = true;
    virtualNetworkInterface_->start();
    thread_ = std::thread(&VirtualInterface::run, this);
    return thread_.joinable();
}

bool VirtualInterface::stop() noexcept
{
    running_ = false;
    virtualNetworkInterface_->stop();
    if (thread_.joinable()) {
        iptables_->clean();
        thread_.join();
        return true;
    }
    return false;
}

void VirtualInterface::run() noexcept
{
    const auto timeout = std::chrono::milliseconds(300);
    std::this_thread::sleep_for(std::chrono::seconds(1)); // FIX IT!
    iptables_->apply(); // activate route
    while(running_) {
        auto packet = toNetwork_.waitForPacket(timeout);
        if (packet != nullptr) {
            virtualNetworkInterface_->send(std::move(packet));
        }
    }
}

void VirtualInterface::newIPPacketFromNetwork(fptn::common::network::IPPacketPtr packet) noexcept
{
    fromNetwork_.push(std::move(packet));
}
