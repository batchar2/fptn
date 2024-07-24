#include "iptables.h"

#include <vector>

#include <fmt/format.h>
#include <glog/logging.h>
#include <boost/process.hpp>


using namespace fptn::system;

static bool runCommand(const std::string& command);


IPTables::IPTables(
    const std::string& outInterfaceName,
    const std::string& tunInterfaceName
) : 
    init_(false),
    outInterfaceName_(outInterfaceName),
    tunInterfaceName_(tunInterfaceName)
{
}


IPTables::~IPTables()
{
    clean();
}


bool IPTables::check() noexcept
{
    return true;
}


bool IPTables::apply() noexcept
{
    LOG(INFO)<< "=== Setting up routing ===";
#ifdef __linux__ 
    const std::vector<std::string> commands = {
        "echo 1 > /proc/sys/net/ipv4/ip_forward",
        "iptables -P INPUT ACCEPT",
        "iptables -P FORWARD ACCEPT",
        "iptables -P OUTPUT ACCEPT",
        fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, outInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", outInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE", outInterfaceName_)
    };
#elif __APPLE__
    // NEED CHECK
    const std::vector<std::string> commands = {
        fmt::format("echo 'set skip on lo0' > /tmp/pf.conf"),
        fmt::format("echo 'block in all' >> /tmp/pf.conf"),
        fmt::format("echo 'pass out all' >> /tmp/pf.conf"),
        fmt::format("echo 'block in on {} from any to any' >> /tmp/pf.conf", outInterfaceName_),
        "pfctl -ef /tmp/pf.conf",
    };
#else
    #error "Unsupported system!"
#endif
    init_ = true;
    for (const auto& cmd : commands) {
        if (!runCommand(cmd)) {
            LOG(WARNING) << "COMMAND ERORR: " << cmd;
        }
    }
    LOG(INFO)<< "=== Routing setup completed successfully ===";
    return true;
}


bool IPTables::clean() noexcept
{
#ifdef __linux__ 
    const std::vector<std::string> commands = {
        fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, outInterfaceName_),
        fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", outInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE", outInterfaceName_),
    };
#elif __APPLE__
    const std::vector<std::string> commands = {
        "echo 'set skip on lo0' > /tmp/pf.conf",
        "echo 'block in all' >> /tmp/pf.conf",
        "echo 'pass out all' >> /tmp/pf.conf",
        fmt::format("echo 'pass in on {} from any to any' >> /tmp/pf.conf", outInterfaceName_),
        fmt::format("echo 'pass in on {} from {} to any' >> /tmp/pf.conf", tunInterfaceName_, tunInterfaceName_),
        "pfctl -f /tmp/pf.conf",
        "pfctl -e"
    };
#else
    #error "Unsupported system!"
#endif
    if (init_) {
        for (const auto& cmd : commands) {
            runCommand(cmd); 
        }
    }
    return true;
}


static bool runCommand(const std::string& command) 
{
    try {
        boost::process::child child(command, boost::process::std_out > stdout, boost::process::std_err > stderr);
        child.wait();
        if (child.exit_code() == 0) {
            return true;
        }
    } catch (const std::exception& e) {
        LOG(ERROR)<< "IPTables error: " << e.what();
    }
    return false;
}
