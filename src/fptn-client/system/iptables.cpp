#include "iptables.h"

#include <vector>

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#if _WIN32
static std::string getWindowsInterfaceNumber(const std::string& interfaceName);
#endif

#include <common/system/command.h>


using namespace fptn::system;


IPTables::IPTables(
    const std::string& outInterfaceName,
    const std::string& tunInterfaceName,
    const pcpp::IPv4Address& vpnServerIP,
    const pcpp::IPv4Address& dnsServerIPv4,
    const pcpp::IPv6Address& dnsServerIPv6,
    const pcpp::IPv4Address& gatewayIp,
    const pcpp::IPv4Address& tunInterfaceAddressIPv4,
    const pcpp::IPv6Address& tunInterfaceAddressIPv6
) :
        init_(false),
        outInterfaceName_(outInterfaceName),
        tunInterfaceName_(tunInterfaceName),
        vpnServerIP_(vpnServerIP),
        dnsServerIPv4_(dnsServerIPv4),
        dnsServerIPv6_(dnsServerIPv6),
        gatewayIp_(gatewayIp),
        tunInterfaceAddressIPv4_(tunInterfaceAddressIPv4),
        tunInterfaceAddressIPv6_(tunInterfaceAddressIPv6)
{
}

IPTables::~IPTables()
{
    if (init_) {
        clean();
    }
}

bool IPTables::check() noexcept
{
    return true;
}

bool IPTables::apply() noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    init_ = true;
#if defined(__APPLE__) || defined(__linux__)
    findOutInterfaceName_ = (outInterfaceName_.empty() ? getDefaultNetworkInterfaceName() : outInterfaceName_);
#endif
    findOutGatewayIp_ = (gatewayIp_ == pcpp::IPv4Address("0.0.0.0") ? getDefaultGatewayIPAddress() : gatewayIp_);

    SPDLOG_INFO("=== Setting up routing ===");
    SPDLOG_INFO("IPTABLES VPN SERVER IP:         {}", vpnServerIP_.toString());
    SPDLOG_INFO("IPTABLES OUT NETWORK INTERFACE: {}", findOutInterfaceName_);
    SPDLOG_INFO("IPTABLES GATEWAY IP:            {}", findOutGatewayIp_.toString());
    SPDLOG_INFO("IPTABLES DNS SERVER:            {}", dnsServerIPv4_.toString());
#ifdef __linux__
    const std::vector<std::string> commands = {
        // forwarding
        fmt::format("systemctl start sysctl"),
        fmt::format("sysctl -w net.ipv4.ip_forward=1"),
        fmt::format("sysctl -w net.ipv6.conf.default.disable_ipv6=0"),
        fmt::format("sysctl -w net.ipv6.conf.all.disable_ipv6=0"),
        fmt::format("sysctl -w net.ipv6.conf.lo.disable_ipv6=0"),
        fmt::format("sysctl -w net.ipv6.conf.all.forward=1"),
        fmt::format("sysctl -p"),
        // iptables
        fmt::format("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE", findOutInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT", findOutInterfaceName_, tunInterfaceName_),
        fmt::format("iptables -A FORWARD -i {} -o {} -j ACCEPT", tunInterfaceName_, findOutInterfaceName_),
        fmt::format("iptables -A OUTPUT -o {} -d {} -j ACCEPT", findOutInterfaceName_, vpnServerIP_.toString()),
        fmt::format("iptables -A INPUT -i {} -s {} -j ACCEPT", findOutInterfaceName_, vpnServerIP_.toString()),
        // IPv4 default & DNS route
        fmt::format("ip route add default dev {}", tunInterfaceName_),
        fmt::format("ip route add {} dev {}", dnsServerIPv4_.toString(), tunInterfaceName_), // via TUN
        // IPv6 default
        fmt::format("ip -6 route add default dev {}", tunInterfaceName_),
        // exclude vpn server & networks
        fmt::format("ip route add {} via {} dev {}", vpnServerIP_.toString(), findOutGatewayIp_.toString(), findOutInterfaceName_),
        fmt::format("ip route add 10.0.0.0/8 via {} dev {}", findOutGatewayIp_.toString(), findOutInterfaceName_),
        fmt::format("ip route add 172.16.0.0/12 via {} dev {}", findOutGatewayIp_.toString(), findOutInterfaceName_),
        fmt::format("ip route add 192.168.0.0/16 via {} dev {}", findOutGatewayIp_.toString(), findOutInterfaceName_),
        // DNS
        fmt::format("resolvectl dns {} {}", tunInterfaceName_, dnsServerIPv4_.toString()),
        fmt::format("resolvectl domain {} \"~.\" ", tunInterfaceName_),
        fmt::format("resolvectl default-route {} yes", tunInterfaceName_)
    };
#elif __APPLE__
    const std::vector<std::string> commands = {
        fmt::format(R"(bash -c "networksetup -listallnetworkservices | grep -v '^An asterisk' | xargs -I {{}} networksetup -setdnsservers '{{}}' empty")", dnsServerIPv4_.toString()), // clean DNS
        fmt::format("sudo sysctl -w net.inet.ip.forwarding=1"),
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
        fmt::format("sudo pfctl -ef /tmp/pf.conf"),
        // default & DNS route
        fmt::format("sudo route add -net 0.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("sudo route add -net 128.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("sudo route add -host {} -interface {}", dnsServerIPv4_.toString(), tunInterfaceName_), // via TUN
        // exclude vpn server & networks
        fmt::format("sudo route add -host {} {}", vpnServerIP_.toString(), findOutGatewayIp_.toString()),
        fmt::format("sudo route add -net 10.0.0.0/8 {}", findOutGatewayIp_.toString()),
        fmt::format("sudo route add -net 172.16.0.0/12 {}", findOutGatewayIp_.toString()),
        fmt::format("sudo route add -net 192.168.0.0/16 {}", findOutGatewayIp_.toString()),
        // DNS
        fmt::format("sudo dscacheutil -flushcache"),
        fmt::format(R"(bash -c "sudo networksetup -listallnetworkservices | grep -v '^\* ' | xargs -I {{}} networksetup -setdnsservers '{{}}' {}")", dnsServerIPv4_.toString())
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
        fmt::format("route add 0.0.0.0 mask 0.0.0.0 {} METRIC 1 {}", tunInterfaceAddressIPv4_.toString(), interfaceInfo),
        fmt::format("route add {} mask 255.255.255.255 {} METRIC 2 {}", dnsServerIPv4_.toString(), tunInterfaceAddressIPv4_.toString(), interfaceInfo), // via TUN
        // DNS
        fmt::format("netsh interface ip set dns name=\"{}\" static {}", tunInterfaceName_, dnsServerIPv4_.toString()),
        // IPv6
        fmt::format("netsh interface ipv6 add route ::/0 \"{}\" \"{}\" ", tunInterfaceName_, tunInterfaceAddressIPv6_.toString()),
        fmt::format("netsh interface ipv6 add dnsservers=\"{}\" \"{}\" index=1", tunInterfaceName_, dnsServerIPv6_.toString())
    };
#else
    #error "Unsupported system!"
#endif
    for (const auto& cmd : commands) {
        fptn::common::system::command::run(cmd);
    }
    SPDLOG_INFO("=== Routing setup completed successfully ===");
    return true;
}

bool IPTables::clean() noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    if (!init_) {
        SPDLOG_INFO("No need to clean rules!");
        return true;
    }
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
        fmt::format("route delete -host {} -interface {}", dnsServerIPv4_.toString(), tunInterfaceName_), // via TUN
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
        fmt::format("route delete 0.0.0.0 mask 0.0.0.0 {}", tunInterfaceAddressIPv4_.toString()),
        fmt::format("route delete 10.0.0.0 mask 255.0.0.0 {}", findOutGatewayIp_.toString()),
        fmt::format("route delete 172.16.0.0 mask 255.240.0.0 {}", findOutGatewayIp_.toString()),
        fmt::format("route delete 192.168.0.0 mask 255.255.0.0 {}", findOutGatewayIp_.toString()),
        // DNS
        fmt::format("netsh interface ip set dns name=\"{}\" dhcp", findOutInterfaceName_),
        fmt::format("route delete {} mask 255.255.255.255 {} METRIC 2 {}", dnsServerIPv4_.toString(), tunInterfaceAddressIPv4_.toString(), interfaceInfo), // via TUN
        // IPv6
        fmt::format("netsh interface ipv6 delete dnsservers \"{}\" {}", tunInterfaceName_, dnsServerIPv6_.toString())
    };
#else
    #error "Unsupported system!"
#endif
    for (const auto& cmd : commands) {
        fptn::common::system::command::run(cmd);
    }
    init_ = false;
    return true;
}


pcpp::IPv4Address fptn::system::resolveDomain(const std::string& domain) noexcept
{
    try {
        try {
            // error test
            boost::asio::ip::make_address(domain);
            return domain;
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
        SPDLOG_ERROR("Error resolving domain: {}", e.what());
    }
    return domain;
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
        std::vector<std::string> stdoutput;
        fptn::common::system::command::run(command, stdoutput);
        for (const auto& line : stdoutput) {
            std::string result = line;
            result.erase(
                std::remove_if(
                    result.begin(), result.end(), [](char c) {
                        return !std::isdigit(c) && c != '.';
                    }
                ),
                result.end()
            );
            if (!result.empty() && pcpp::IPv4Address(result) != pcpp::IPv4Address("0.0.0.0")) {
                return result;
            }
        }
    } catch (const std::exception& ex) {
        SPDLOG_ERROR("Error: Failed to retrieve the default gateway IP address. {}", ex.what());
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
#endif
        std::vector<std::string> stdoutput;
        fptn::common::system::command::run(command, stdoutput);
        if (stdoutput.empty()) {
            spdlog::warn("Warning: Default gateway IP address not found.");
            return {};
        }
        for (const auto& line : stdoutput) {
            result = line;
            result.erase(result.find_last_not_of(" \n\r\t") + 1);
            result.erase(0, result.find_first_not_of(" \n\r\t"));
        }
    } catch (const std::exception& ex) {
        SPDLOG_ERROR("Error: Failed to retrieve the default gateway IP address. {}", ex.what());
    }
    return result;
}

#if _WIN32
std::string getWindowsInterfaceNumber(const std::string& interfaceName)
{
    try {
        const std::string command = "powershell -Command \"(Get-NetAdapter -Name '" + interfaceName + "').ifIndex\"";
        std::vector<std::string> stdoutput;
        fptn::common::system::command::run(command, stdoutput);

        if (stdoutput.empty()) {
            spdlog::warn("Warning: Interface index not found.");
            return {};
        }
        for (const auto& line : stdoutput) {
            std::string result = line;
            result.erase(result.find_last_not_of(" \n\r\t") + 1);
            result.erase(0, result.find_first_not_of(" \n\r\t"));
            if (!result.empty() && std::all_of(result.begin(), result.end(), ::isdigit)) {
                return result;
            }
        }
        SPDLOG_ERROR("Error: Invalid interface index format.");
        return {};
    } catch (const std::exception& ex) {
        SPDLOG_ERROR("Error: failed to retrieve the interface index. Msg: {}", ex.what());
    }
    return {};
}
#endif
