#include "iptables.h"

#include <vector>

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <boost/asio.hpp>
#include <boost/process.hpp>
#if _WIN32
#include <VersionHelpers.h>
#include <boost/process/windows.hpp>
#endif


using namespace fptn::system;


static bool runCommand(const std::string& command);

#if _WIN32
static std::string getWindowsInterfaceNumber(const std::string& interfaceName);
#endif

IPTables::IPTables(
    const std::string& outInterfaceName,
    const std::string& tunInterfaceName,
    const pcpp::IPv4Address& vpnServerIP,
    const pcpp::IPv4Address& dnsServer,
    const pcpp::IPv4Address& gatewayIp,
    const pcpp::IPv4Address& tunInterfaceAddress
) :
    init_(false),
    outInterfaceName_(outInterfaceName),
    tunInterfaceName_(tunInterfaceName),
    vpnServerIP_(vpnServerIP),
    dnsServer_(dnsServer),
    gatewayIp_(gatewayIp),
    tunInterfaceAddress_(tunInterfaceAddress)
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
    findOutInterfaceName_ = (outInterfaceName_.empty() ? getDefaultNetworkInterfaceName() : outInterfaceName_);
    findOutGatewayIp_ = (gatewayIp_ == pcpp::IPv4Address("0.0.0.0") ? getDefaultGatewayIPAddress() : gatewayIp_);

    spdlog::info("=== Setting up routing ===");
    spdlog::info("IPTABLES VPN SERVER IP:         {}", vpnServerIP_.toString());
    spdlog::info("IPTABLES OUT NETWORK INTERFACE: {}", findOutInterfaceName_);
    spdlog::info("IPTABLES GATEWAY IP:            {}", findOutGatewayIp_.toString());
    spdlog::info("IPTABLES DNS SERVER:            {}", dnsServer_.toString());
#ifdef __linux__
    const std::vector<std::string> commands = {
        fmt::format("sysctl -w net.inet.ip.forwarding=1"),
        fmt::format("sysctl -p"),
        fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE", findOutInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", findOutInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, findOutInterfaceName_),
        fmt::format("iptables -A OUTPUT -o {} -d {} -j ACCEPT", findOutInterfaceName_, vpnServerIP_.toString()),
        fmt::format("iptables -A INPUT -i {} -s {} -j ACCEPT", findOutInterfaceName_, vpnServerIP_.toString()),
        // default & DNS route
        fmt::format("ip route add default dev {}", tunInterfaceName_),
        fmt::format("ip route add {} dev {}", dnsServer_.toString(), tunInterfaceName_), // via TUN
        // exclude vpn server & networks
        fmt::format("ip route add {} via {} dev {}", vpnServerIP_.toString(), findOutGatewayIp_.toString(), findOutInterfaceName_),
        fmt::format("ip route add 10.0.0.0/8 via {} dev {}", findOutGatewayIp_.toString(), findOutInterfaceName_),
        fmt::format("ip route add 172.16.0.0/12 via {} dev {}", findOutGatewayIp_.toString(), findOutInterfaceName_),
        fmt::format("ip route add 192.168.0.0/16 via {} dev {}", findOutGatewayIp_.toString(), findOutInterfaceName_),
        // DNS
        fmt::format("resolvectl dns {} {}", tunInterfaceName_, dnsServer_.toString()),
        fmt::format("resolvectl domain {} \"~.\" ", tunInterfaceName_),
        fmt::format("resolvectl default-route {} yes", tunInterfaceName_)
    };
#elif __APPLE__
    const std::vector<std::string> commands = {
        fmt::format(R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")", dnsServer_.toString()), // clean DNS
        fmt::format("sysctl -w net.inet.ip.forwarding=1"),
        fmt::format(
            R"(sh -c "echo 'nat on {findOutInterfaceName} from {tunInterfaceName}:network to any -> ({findOutInterfaceName})
                pass out on {findOutInterfaceName} proto tcp from any to {vpnServerIP}
                pass in on {findOutInterfaceName} proto tcp from {vpnServerIP} to any
                pass in on {tunInterfaceName} proto tcp from any to any
                pass out on {tunInterfaceName} proto tcp from any to any' > /tmp/pf.conf"
            )",
            fmt::arg("findOutInterfaceName", findOutInterfaceName_),
            fmt::arg("tunInterfaceName", tunInterfaceName_),
            fmt::arg("vpnServerIP", vpnServerIP_.toString())
        ),
        fmt::format("pfctl -ef /tmp/pf.conf"),
        // default & DNS route
        fmt::format("route add -net 0.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route add -net 128.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route add -host {} -interface {}", dnsServer_.toString(), tunInterfaceName_), // via TUN
        // exclude vpn server & networks
        fmt::format("route add -host {} {}", vpnServerIP_.toString(), findOutGatewayIp_.toString()),
        fmt::format("route add -net 10.0.0.0/8 {}", findOutGatewayIp_.toString()),
        fmt::format("route add -net 172.16.0.0/12 {}", findOutGatewayIp_.toString()),
        fmt::format("route add -net 192.168.0.0/16 {}", findOutGatewayIp_.toString()),
        // DNS
        fmt::format("dscacheutil -flushcache"),
        fmt::format(R"(bash -c "networksetup -listallnetworkservices | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' {}")", dnsServer_.toString())
    };
#elif _WIN32
    const std::string winInterfaceNumber = getWindowsInterfaceNumber(tunInterfaceName_);
    const std::string interfaceInfo = winInterfaceNumber.empty() ? "" : " if " + winInterfaceNumber;
    const std::vector<std::string> commands = {
        // exclude vpn server & networks
        fmt::format("netsh interface ip set dns name=\"{}\" dhcp", tunInterfaceName_), // CLEAN DNS
        fmt::format("route add {} mask 255.255.255.255 {} METRIC 2", vpnServerIP_.toString(), findOutGatewayIp_.toString()),
        fmt::format("route add 10.0.0.0 mask 255.0.0.0 {} METRIC 2", findOutGatewayIp_.toString()),
        fmt::format("route add 172.16.0.0 mask 255.240.0.0 {} METRIC 2", findOutGatewayIp_.toString()),
        fmt::format("route add 192.168.0.0 mask 255.255.0.0 {} METRIC 2", findOutGatewayIp_.toString()),
        // Default gateway & dns
        fmt::format("route add 0.0.0.0 mask 0.0.0.0 {} METRIC 1 {}", tunInterfaceAddress_.toString(), interfaceInfo),
        fmt::format("route add {} mask 255.255.255.255 {} METRIC 2 {}", dnsServer_.toString(), tunInterfaceAddress_.toString(), interfaceInfo), // via TUN
        // DNS
        fmt::format("netsh interface ip set dns name=\"{}\" static {}", tunInterfaceName_, dnsServer_.toString())
    };
#else
    #error "Unsupported system!"
#endif
    init_ = true;
    for (const auto& cmd : commands) {
        if (!runCommand(cmd)) {
            spdlog::warn("COMMAND ERORR: {}", cmd);
        }
    }
    spdlog::info("=== Routing setup completed successfully ===");
    return true;
}

bool IPTables::clean() noexcept
{
#ifdef __linux__
    const std::vector<std::string> commands = {
        fmt::format("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE", findOutInterfaceName_),
        fmt::format("iptables -D FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", findOutInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -D FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, findOutInterfaceName_),
        fmt::format("iptables -D OUTPUT -o {} -d {} -j ACCEPT", findOutInterfaceName_, vpnServerIP_.toString()),
        fmt::format("iptables -D INPUT -i {} -s {} -j ACCEPT", findOutInterfaceName_, vpnServerIP_.toString()),
        // del routes
        fmt::format("ip route del default dev {}", tunInterfaceName_),
        fmt::format("ip route del {} via {} dev {}", vpnServerIP_.toString(), findOutGatewayIp_.toString(), findOutInterfaceName_),
        fmt::format("ip route del 10.0.0.0/8 via {} dev {}", findOutGatewayIp_.toString(), findOutInterfaceName_),
        fmt::format("ip route del 172.16.0.0/12 via {} dev {}", findOutGatewayIp_.toString(), findOutInterfaceName_),
        fmt::format("ip route del 192.168.0.0/16 via {} dev {}", findOutGatewayIp_.toString(), findOutInterfaceName_),
        // DNS
        fmt::format("resolvectl dns {} '' ", tunInterfaceName_),
        fmt::format("resolvectl domain {} '' ", findOutInterfaceName_),
        fmt::format("resolvectl default-route {} no '' ", findOutInterfaceName_)
    };
#elif __APPLE__
    const std::vector<std::string> commands = {
        fmt::format(R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")"), // clean DNS
        fmt::format("pfctl -F all -f /etc/pf.conf"),
        // del routes
        fmt::format("route delete -host {} -interface {}", dnsServer_.toString(), tunInterfaceName_), // via TUN
        fmt::format("route delete -net 0.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route delete -net 128.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route delete -host {} {}", vpnServerIP_.toString(), findOutGatewayIp_.toString()),
        fmt::format("route delete -net 10.0.0.0/8 {}", findOutGatewayIp_.toString()),
        fmt::format("route delete -net 172.16.0.0/12 {}", findOutGatewayIp_.toString()),
        fmt::format("route delete -net 192.168.0.0/16 {}", findOutGatewayIp_.toString()),
        // DNS
        fmt::format(R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")") // clean DNS
    };
#elif _WIN32
    const std::string winInterfaceNumber = getWindowsInterfaceNumber(tunInterfaceName_);
    const std::string interfaceInfo = winInterfaceNumber.empty() ? "" : " if " + winInterfaceNumber;
    const std::vector<std::string> commands = {
        // del routes
        fmt::format("route delete {} mask 255.255.255.255 {}", vpnServerIP_.toString(), findOutGatewayIp_.toString()),
        fmt::format("route delete 0.0.0.0 mask 0.0.0.0 {}", tunInterfaceAddress_.toString()),
        fmt::format("route delete 10.0.0.0 mask 255.0.0.0 {}", findOutGatewayIp_.toString()),
        fmt::format("route delete 172.16.0.0 mask 255.240.0.0 {}", findOutGatewayIp_.toString()),
        fmt::format("route delete 192.168.0.0 mask 255.255.0.0 {}", findOutGatewayIp_.toString()),
        // DNS
        fmt::format("netsh interface ip set dns name=\"{}\" dhcp", tunInterfaceName_),
        fmt::format("route delete {} mask 255.255.255.255 {} METRIC 2 {}", dnsServer_.toString(), tunInterfaceAddress_.toString(), interfaceInfo) // via TUN
    };
#else
    #error "Unsupported system!"
#endif
    if (init_) {
        for (const auto& cmd : commands) {
            /*LOG(INFO) << "CLEAN: " << cmd;*/
            runCommand(cmd);
        }
    }
    return true;
}

static bool runCommand(const std::string& command)
{
    try {
#ifdef _WIN32
        boost::process::child child(command, boost::process::std_out > stdout, boost::process::std_err > stderr, ::boost::process::windows::hide);
#else
        boost::process::child child(command, boost::process::std_out > stdout, boost::process::std_err > stderr);
#endif
        child.wait();
        spdlog::info("RUN: " + command);
        if (child.exit_code() == 0) {
            return true;
        }
    } catch (const std::exception& e) {
        const std::string msg = e.what();
        spdlog::error("IPTables error: " + msg);
    } catch (...) {
        spdlog::error("Undefined command error");
    }
    return false;
}

pcpp::IPv4Address fptn::system::resolveDomain(const std::string& domain) noexcept
{
    try {
        // Check if the domain is already an IP address
        boost::asio::ip::address ip_address;
        try {
            ip_address = boost::asio::ip::make_address(domain);
            return pcpp::IPv4Address(domain);
        } catch (const std::exception&) {
            // Not a valid IP address, proceed with domain name resolution
        }
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::resolver resolver(io_context);
        boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(domain, "");
        for (const auto& endpoint : endpoints) {
            return pcpp::IPv4Address(endpoint.endpoint().address().to_string());
        }
    } catch (const std::exception& e) {
        spdlog::error("Error resolving domain: {}", e.what());
    }
    return pcpp::IPv4Address(domain);
}

pcpp::IPv4Address fptn::system::getDefaultGatewayIPAddress() noexcept
{
    try
    {
#ifdef __linux__
        const std::string command = "ip route get 8.8.8.8 | awk '{print $3; exit}'";
#elif __APPLE__
        const std::string command = "route get 8.8.8.8 | grep gateway | awk '{print $2}' ";
#elif _WIN32
        const std::string command = R"(cmd.exe /c FOR /f "tokens=3" %i in ('route print ^| find "0.0.0.0"') do @echo %i)";
#else
        #error "Unsupported system!"
#endif
        boost::process::ipstream pipe;
#ifdef _WIN32
        boost::process::child child(command, boost::process::std_out > pipe, ::boost::process::windows::hide);
#else
        boost::process::child child(
            boost::process::search_path("bash"), "-c", command,
            boost::process::std_out > pipe
        );
#endif
        std::string result;
        while (std::getline(pipe, result)) {
            result.erase(
                std::remove_if(
                    result.begin(), result.end(), [](char c) {
                        return !std::isdigit(c) && c != '.';
                    }
                ),
                result.end()
            );
            if (!result.empty() && pcpp::IPv4Address(result) != pcpp::IPv4Address("0.0.0.0")) {  
                return pcpp::IPv4Address(result);
            }
        }
        child.wait();
    } catch (const std::exception& ex) {
        spdlog::error("Error: Failed to retrieve the default gateway IP address. {}", ex.what());
    }
    return {};
}

std::string fptn::system::getDefaultNetworkInterfaceName() noexcept
{
    std::string result;
    try
    {
#ifdef __linux__
        const std::string command = "ip route get 8.8.8.8 | awk '{print $5; exit}' ";
#elif __APPLE__
        const std::string command = "route get 8.8.8.8 | grep interface | awk '{print $2}' ";
#elif _WIN32
        const std::string command = R"(cmd.exe /c "FOR /F "tokens=1,2,3" %i IN ('route print ^| findstr /R /C:"0.0.0.0"') DO @echo %i")";
#else
        #error "Unsupported system!"
#endif
        boost::process::ipstream pipe;
#ifdef _WIN32
        boost::process::child child(command, boost::process::std_out > pipe, ::boost::process::windows::hide);
#else
        boost::process::child child(
            boost::process::search_path("bash"), "-c", command,
            boost::process::std_out > pipe
        );
        std::getline(pipe, result);
        child.wait();
        if (result.empty()) {
            spdlog::warn("Warning: Default gateway IP address not found.");
            return {};
        }
        result.erase(result.find_last_not_of(" \n\r\t") + 1);
        result.erase(0, result.find_first_not_of(" \n\r\t"));
#endif
    } catch (const std::exception& ex) {
        spdlog::error("Error: Failed to retrieve the default gateway IP address. {}", ex.what());
    }
    return result;
}

#if _WIN32
std::string getWindowsInterfaceNumber(const std::string& interfaceName)
{
    std::string result;
    try {
        const std::string command = "powershell -Command \"(Get-NetAdapter -Name '" + interfaceName + "').ifIndex\"";
        boost::process::ipstream pipe_stream;
        boost::process::child child(command, boost::process::std_out > pipe_stream, ::boost::process::windows::hide);
        std::getline(pipe_stream, result);
        child.wait();

        // Check if result is empty
        if (result.empty()) {
            std::cerr << "Warning: Interface index not found." << std::endl;
            return {};
        }
        result.erase(result.find_last_not_of(" \n\r\t") + 1);
        result.erase(0, result.find_first_not_of(" \n\r\t"));
        if (result.empty() || !std::all_of(result.begin(), result.end(), ::isdigit)) {
            std::cerr << "Error: Invalid interface index format." << std::endl;
            return "";
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: Failed to retrieve the interface index. " << ex.what() << std::endl;
    }
    return result;
}
#endif
