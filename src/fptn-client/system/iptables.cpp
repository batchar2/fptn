#include "iptables.h"

#include <vector>

#include <fmt/format.h>
#include <glog/logging.h>

#include <boost/asio.hpp>
#include <boost/process.hpp>
#if _WIN32
    #include <VersionHelpers.h>
    #include <boost/process/windows.hpp>
#endif


using namespace fptn::system;


static std::string getDefaultGatewayIPAddress();
static bool runCommand(const std::string& command);
static std::string resolveDomain(const std::string& domain);
#if _WIN32
static std::string getWindowsInterfaceNumber(const std::string& interfaceName);
static bool isWindows11();
#endif

IPTables::IPTables(
    const std::string& outInterfaceName,
    const std::string& tunInterfaceName,
    const std::string& vpnServerIp,
    const std::string& gatewayIp,
    const std::string& tunInterfaceAddress
) : 
    init_(false),
    outInterfaceName_(outInterfaceName),
    tunInterfaceName_(tunInterfaceName),
    vpnServerIp_(vpnServerIp),
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
    const std::string vpnServerIP = resolveDomain(vpnServerIp_);

    LOG(INFO) << "Resolve: " << vpnServerIp_ << " --> " << vpnServerIP;
    LOG(INFO)<< "=== Setting up routing ===";
#ifdef __linux__ 
    const std::vector<std::string> commands = {
        fmt::format("sysctl -w net.inet.ip.forwarding=1"),
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
    const std::string winInterfaceNumber = getWindowsInterfaceNumber(tunInterfaceName_);
    const std::string interfaceInfo = winInterfaceNumber.empty() ? "" : " if " + winInterfaceNumber;
    // const std::string win11Route = isWindows11() ? "netsh interface ipv4 set global forwarding=enabled" : "dir";
    const std::string win11Route = "netsh interface ipv4 set global forwarding=enabled";
    const std::vector<std::string> commands = {
        win11Route,
        fmt::format("route add {} mask 255.255.255.255 {} METRIC 2", vpnServerIP, gatewayIp_),
        fmt::format("route add 0.0.0.0 mask 0.0.0.0 {} METRIC 1 {}", tunInterfaceAddress_, interfaceInfo),
    };
#else
    #error "Unsupported system!"
#endif
    init_ = true;
    for (const auto& cmd : commands) {
        LOG(INFO) << "cmd: " << cmd;
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
        fmt::format("pfctl -F all -f /etc/pf.conf"),
        fmt::format("route delete -net 0.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route delete -net 128.0.0.0/1 -interface {}", tunInterfaceName_),
        fmt::format("route delete {} {}", vpnServerIP, gatewayIp_)
    };
#elif _WIN32
    const std::vector<std::string> commands = {
        fmt::format("route delete {} mask 255.255.255.255 {}", vpnServerIP, gatewayIp_),
        fmt::format("route delete 0.0.0.0 mask 0.0.0.0 {}", tunInterfaceAddress_)
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
#ifdef _WIN32
        boost::process::child child(command, boost::process::std_out > stdout, boost::process::std_err > stderr, ::boost::process::windows::hide);
#else
        boost::process::child child(command, boost::process::std_out > stdout, boost::process::std_err > stderr);
#endif
        child.wait();
        if (child.exit_code() == 0) {
            return true;
        }
    } catch (const std::exception& e) {
        LOG(ERROR)<< "IPTables error: " << e.what();
    } catch (...) {
        LOG(ERROR)<< "Undefined command error";
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
    try 
    {
#ifdef __linux__ 
        const std::string command = R"(ip route | grep default | awk '{print $3}')";
#elif __APPLE__
        const std::string command = R"(netstat -rn | grep default | awk '{print $2}')";
#elif _WIN32
        const std::string command = R"(cmd.exe /c FOR /F "tokens=13" %x IN ('ipconfig ^| findstr "Default Gateway" ^| findstr /R "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*"') DO @echo %x)";
#else
    #error "Unsupported system!"
#endif
        boost::process::ipstream pipe_stream;

#ifdef _WIN32
        boost::process::child child(command, boost::process::std_out > pipe_stream, ::boost::process::windows::hide);
#else
        boost::process::child child(command, boost::process::std_out > pipe_stream);
#endif
        std::getline(pipe_stream, result);
        child.wait();
        if (result.empty()) {
            LOG(ERROR)<< "Warning: Default gateway IP address not found.";
            return "";
        }
        // Remove all characters except digits and dots
        result.erase(
            std::remove_if(
                result.begin(), result.end(), [](char c) {
                    return !std::isdigit(c) && c != '.';
                }
            ), 
            result.end()
        );
        result.erase(result.find_last_not_of(" \n\r\t") + 1);
        result.erase(0, result.find_first_not_of(" \n\r\t"));
    } catch (const std::exception& ex) {
        LOG(ERROR) << "Error: Failed to retrieve the default gateway IP address. " << ex.what();
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
            return "";
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


static bool isWindows11() {
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    osvi.dwMajorVersion = 10; // Windows 10 and later
    osvi.dwMinorVersion = 0;

    // Get the version information
    if (GetVersionExW(reinterpret_cast<OSVERSIONINFOW*>(&osvi))) {
        // Windows 11 has a major version of 10 and a build number of 22000 or higher
        if (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber >= 22000) {
            return true;
        }
    }

    return false;
}
#endif
