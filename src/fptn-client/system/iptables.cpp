#include "iptables.h"

#include <vector>

#include <fmt/format.h>
#include <glog/logging.h>

#include <boost/asio.hpp>
#include <boost/process.hpp>


using namespace fptn::system;


static std::string getDefaultGatewayIPAddress();
static bool runCommand(const std::string& command);
static std::string resolveDomain(const std::string& domain);


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
    const std::string vpnServerIP = resolveDomain(vpnServerIp_);

    LOG(INFO) << "Resolve: " << vpnServerIp_ << " --> " << vpnServerIP;
    LOG(INFO)<< "=== Setting up routing ===";
#ifdef __linux__ 
    const std::vector<std::string> commands = {
        "sysctl -w net.ipv4.ip_forward=1",
        fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE", outInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", outInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, outInterfaceName_),
        fmt::format("iptables -A OUTPUT -o {} -d {} -j ACCEPT", outInterfaceName_, vpnServerIP),
        fmt::format("iptables -A INPUT -i {} -s {} -j ACCEPT", outInterfaceName_, vpnServerIP),
        fmt::format("ip route add default dev {}", tunInterfaceName_),
        fmt::format("ip route add {} via {} dev {}", vpnServerIP, gatewayIp_, outInterfaceName_)
    };
#elif __APPLE__
    const std::vector<std::string> commands = {
        fmt::format("sysctl -w net.inet.ip.forwarding=1"),
        fmt::format("sh -c \"echo 'nat on {} from {}:network to any -> ({})' > /tmp/pf.conf\"", outInterfaceName_, tunInterfaceName_, outInterfaceName_),
        fmt::format("sh -c \"echo 'pass out on {} proto tcp from any to {}' >> /tmp/pf.conf\"", outInterfaceName_, vpnServerIP),
        fmt::format("sh -c \"echo 'pass in on {} proto tcp from {} to any' >> /tmp/pf.conf\"", outInterfaceName_, vpnServerIP),
        fmt::format("sh -c \"echo 'pass in on {} proto tcp from any to any' >> /tmp/pf.conf\"", tunInterfaceName_),
        fmt::format("sh -c \"echo 'pass out on {} proto tcp from any to any' >> /tmp/pf.conf\"", tunInterfaceName_),
        fmt::format("pfctl -ef /tmp/pf.conf"),
        fmt::format("route add -net 0.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route add -net 128.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route add {} {}", vpnServerIP, gatewayIp_)
    };
#elif _WIN32
    const std::vector<std::string> commands = {
        "netsh interface ipv4 set global forwarding=enabled",
        fmt::format("netsh routing ip nat add interface \"{}\" full", outInterfaceName_),
        fmt::format("netsh routing ip nat add interface \"{}\" private", tunInterfaceName_),
        fmt::format("route add 0.0.0.0 mask 128.0.0.0 {} metric 1", vpnServerIP),
        fmt::format("route add 128.0.0.0 mask 128.0.0.0 {} metric 1", vpnServerIP),
        fmt::format("route add {} {}", vpnServerIP, gatewayIp_)
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
    const std::string vpnServerIP = resolveDomain(vpnServerIp_);
#ifdef __linux__
    const std::vector<std::string> commands = {
        fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE", outInterfaceName_),
        fmt::format("iptables -D FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", outInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, outInterfaceName_),
        fmt::format("iptables -D OUTPUT -o {} -d {} -j ACCEPT", outInterfaceName_, vpnServerIP),
        fmt::format("iptables -D INPUT -i {} -s {} -j ACCEPT", outInterfaceName_, vpnServerIP),
        fmt::format("ip route del default dev {}", tunInterfaceName_),
        fmt::format("ip route del {} via {} dev {}", vpnServerIP, gatewayIp_, outInterfaceName_)
    };
#elif __APPLE__
    const std::vector<std::string> commands = {
        "pfctl -F all -f /etc/pf.conf",
        fmt::format("route delete -net 0.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route delete -net 128.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route delete {} {}", vpnServerIP, gatewayIp_)
    };
#elif _WIN32
    const std::vector<std::string> commands = {
        fmt::format("route delete 0.0.0.0 mask 128.0.0.0 {}", vpnServerIP),
        fmt::format("route delete 128.0.0.0 mask 128.0.0.0 {}", vpnServerIP),
        fmt::format("route delete {}", vpnServerIP),
        fmt::format("netsh routing ip nat delete interface \"{}\"", outInterfaceName_),
        fmt::format("netsh routing ip nat delete interface \"{}\"", tunInterfaceName_),
        "netsh interface ipv4 set global forwarding=disabled"
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

static std::string resolveDomain(const std::string& domain)
{
    try {
        // Check if the domain is already an IP address
        boost::asio::ip::address ip_address;
        try {
            ip_address = boost::asio::ip::make_address(domain);
            return ip_address.to_string();
        } catch (const std::exception&) {
            // Not a valid IP address, proceed with domain name resolution
        }
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::resolver resolver(io_context);
        boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(domain, "");
        for (const auto& endpoint : endpoints) {
            return endpoint.endpoint().address().to_string();
        }
    } catch (const std::exception& e) {
        LOG(ERROR) << "Error resolving domain: " << e.what() << std::endl;
    }
    return domain;
}

std::string fptn::system::getDefaultGatewayIPAddress() 
{
    std::string result;
    try {
#ifdef __linux__ 
        const std::string command = "ip route | grep default | awk '{print $3}'";
#elif __APPLE__
        const std::string command = "netstat -rn | grep default | awk '{print $2}'";
#elif _WIN32
        const std::string command = "";
        return "";
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


