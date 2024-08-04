#include "iptables.h"

#include <vector>

#include <fmt/format.h>
#include <glog/logging.h>
#include <boost/process.hpp>


using namespace fptn::system;

static bool runCommand(const std::string& command);
static std::string getDefaultGatewayIPAddress();


IPTables::IPTables(
    const std::string& outInterfaceName,
    const std::string& tunInterfaceName,
    const std::string& vpnServerIp,
    const std::string& gatewayIp
) : 
    init_(false),
    outInterfaceName_(outInterfaceName),
    tunInterfaceName_(tunInterfaceName),
    vpnServerIp_(vpnServerIp),
    gatewayIp_(gatewayIp)
{
    // gatewayIp_ = getDefaultGatewayIPAddress();
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
        "sysctl -w net.ipv4.ip_forward=1",
        fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE", outInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", outInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, outInterfaceName_),
        fmt::format("iptables -A OUTPUT -o {} -d {} -j ACCEPT", outInterfaceName_, vpnServerIp_),
        fmt::format("iptables -A INPUT -i {} -s {} -j ACCEPT", outInterfaceName_, vpnServerIp_),
        fmt::format("ip route add default dev {}", tunInterfaceName_),
        fmt::format("ip route add {} via {} dev {}", vpnServerIp_, gatewayIp_, outInterfaceName_)
    };
#elif __APPLE__
    const std::vector<std::string> commands = {
        fmt::format("sysctl -w net.inet.ip.forwarding=1"),
        fmt::format("sh -c \"echo 'nat on {} from {}:network to any -> ({})' > /tmp/pf.conf\"", outInterfaceName_, tunInterfaceName_, outInterfaceName_),
        fmt::format("sh -c \"echo 'pass out on {} proto tcp from any to {}' >> /tmp/pf.conf\"", outInterfaceName_, vpnServerIp_),
        fmt::format("sh -c \"echo 'pass in on {} proto tcp from {} to any' >> /tmp/pf.conf\"", outInterfaceName_, vpnServerIp_),
        fmt::format("sh -c \"echo 'pass in on {} proto tcp from any to any' >> /tmp/pf.conf\"", tunInterfaceName_),
        fmt::format("sh -c \"echo 'pass out on {} proto tcp from any to any' >> /tmp/pf.conf\"", tunInterfaceName_),
        fmt::format("pfctl -ef /tmp/pf.conf"),
        fmt::format("route add -net 0.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route add -net 128.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route add {} {}", vpnServerIp_, gatewayIp_)
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
        fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE", outInterfaceName_),
        fmt::format("iptables -D FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", outInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, outInterfaceName_),
        fmt::format("iptables -D OUTPUT -o {} -d {} -j ACCEPT", outInterfaceName_, vpnServerIp_),
        fmt::format("iptables -D INPUT -i {} -s {} -j ACCEPT", outInterfaceName_, vpnServerIp_),
        fmt::format("ip route del default dev {}", tunInterfaceName_),
        fmt::format("ip route del {} via {} dev {}", vpnServerIp_, gatewayIp_, outInterfaceName_)
    };
#elif __APPLE__
    const std::vector<std::string> commands = {
        "pfctl -F all -f /etc/pf.conf",
        fmt::format("route delete -net 0.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route delete -net 128.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route delete {} {}", vpnServerIp_, gatewayIp_)
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

std::string fptn::system::getDefaultGatewayIPAddress() 
{
    std::string result;
    try {
#ifdef __linux__ 
        const std::string command = "ip route | grep default | awk '{print $3}'";
#elif __APPLE__
        const std::string command = "netstat -rn | grep default | awk '{print $2}'";
#else
    #error "Unsupported system!"
#endif
        boost::process::ipstream pipe_stream;
        boost::process::child child(
            "/bin/sh", 
            boost::process::args={"-c", command}, 
            boost::process::std_out > pipe_stream
        );
        std::getline(pipe_stream, result);
        child.wait();

        if (result.empty()) {
            LOG(ERROR)<< "Warning: Default gateway IP address not found.";
            return "";
        }

        // Убираем пробелы по краям строки
        result.erase(result.find_last_not_of(" \n\r\t") + 1); 
    } catch (const std::exception& ex) {
        LOG(ERROR) << "Error: Failed to retrieve the default gateway IP address. " << ex.what();
    }
    return result;
}