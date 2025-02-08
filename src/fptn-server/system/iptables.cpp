#include "iptables.h"

#include <vector>

#include <fmt/format.h>
#include <spdlog/spdlog.h>
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
    const std::unique_lock<std::mutex> lock(mutex_);

    init_ = true;
#ifdef __linux__
    const std::vector<std::string> commands = {
        "systemctl start sysctl",
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl -w net.ipv4.conf.all.rp_filter=0",
        "sysctl -w net.ipv4.conf.default.rp_filter=0",
        "sysctl -w net.ipv6.conf.default.disable_ipv6=0",
        "sysctl -w net.ipv6.conf.all.disable_ipv6=0",
        "sysctl -w net.ipv6.conf.lo.disable_ipv6=0",
        "sysctl -w net.ipv6.conf.all.forwarding=1",
        "sysctl -p",
        /* IPv4 */
        "iptables -P INPUT ACCEPT",
        "iptables -P FORWARD ACCEPT",
        "iptables -P OUTPUT ACCEPT",
        fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, outInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", outInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE", outInterfaceName_),
        /* IPv6 */
        "ip6tables -P INPUT ACCEPT",
        "ip6tables -P FORWARD ACCEPT",
        "ip6tables -P OUTPUT ACCEPT",
        fmt::format("ip6tables -A FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, outInterfaceName_),
        fmt::format("ip6tables -A FORWARD -i {} -o {} -j ACCEPT", outInterfaceName_, tunInterfaceName_),
        fmt::format("ip6tables -t nat -A POSTROUTING -o {} -j MASQUERADE", outInterfaceName_)
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
    spdlog::info("=== Setting up routing ===");
    for (const auto& cmd : commands) {
        if (!runCommand(cmd)) {
            spdlog::error("COMMAND ERORR: {}", cmd);
        }
    }
    spdlog::info("=== Routing setup completed successfully ===");
    return true;
}

bool IPTables::clean() noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    if (!init_) {
        return true;
    }
#ifdef __linux__ 
    const std::vector<std::string> commands = {
        fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, outInterfaceName_),
        fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", outInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE", outInterfaceName_)
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

    for (const auto& cmd : commands) {
        runCommand(cmd);
    }
    init_ = false;
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
        spdlog::error("IPTables error: {}", e.what());
    }
    return false;
}
