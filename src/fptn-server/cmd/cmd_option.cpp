#include <memory>
#include <algorithm>

#include <spdlog/spdlog.h>

#include "cmd_option.h"


using namespace fptn::cmd;


inline bool parseBoolean(const std::string& value) noexcept
{
    std::string lowercasedValue = value;
    std::transform(lowercasedValue.begin(), lowercasedValue.end(), lowercasedValue.begin(), ::tolower);
    return lowercasedValue == "true";
}

CmdOptions::CmdOptions(int argc, char* argv[])
        :
        argc_(argc),
        argv_(argv),
        args_("fptn-server")
{
    // Required arguments
    args_.add_argument("--server-crt")
        .required()
        .help("Path to server.crt file");
    args_.add_argument("--server-key")
        .required()
        .help("Path to server.key file");
    args_.add_argument("--server-pub")
        .required()
        .help("Path to server.pub file");
    args_.add_argument("--out-network-interface")
        .required()
        .help("Network out interface");
    // Optional arguments
    args_.add_argument("--server-port")
        .default_value(443)
        .help("Port number")
        .scan<'i', int>();
    args_.add_argument("--tun-interface-name")
        .default_value("tun0")
        .help("Network interface name");
    /* IPv4 */
    args_.add_argument("--tun-interface-ip")
        .default_value(FPTN_SERVER_DEFAULT_ADDRESS_IP4)
        .help("IP address of the virtual interface");
    args_.add_argument("--tun-interface-network-address")
        .default_value(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP4)
        .help("IP network of the virtual interface");
    args_.add_argument("--tun-interface-network-mask")
        .default_value(16)
        .help("Network mask")
        .scan<'i', int>();
    /* IPv6 */
    args_.add_argument("--tun-interface-ipv6")
        .default_value(FPTN_SERVER_DEFAULT_ADDRESS_IP6)
        .help("IPv6 address of the virtual interface");
    args_.add_argument("--tun-interface-network-ipv6-address")
        .default_value(FPTN_SERVER_DEFAULT_NET_ADDRESS_IP6)
        .help("IPv6 network address of the virtual interface");
    args_.add_argument("--tun-interface-network-ipv6-mask")
        .default_value(64)
        .help("IPv6 network mask")
        .scan<'i', int>();
    args_.add_argument("--userfile")
        .help("Path to users file (default: /etc/fptn/users.list)")
        .default_value("/etc/fptn/users.list");
    args_.add_argument("--use-https")
        .help("Use https")
        .default_value("true");
    // Packet filters
    args_.add_argument("--disable-bittorrent")
        .help("Disable BitTorrent traffic filtering. Use this flag to disable filtering.")
        .default_value("false");
    // Allow prometheus metric
    args_.add_argument("--prometheus-access-key")
        .help("Secret key required for accessing Prometheus metrics. Set this to a secret value if metrics is needed.")
        .default_value("");
    // Remote server auth
    args_.add_argument("--use-remote-server-auth")
        .help("Enable remote server authentication. Set to 'true' to use a remote server for authentication.")
        .default_value("false");
    args_.add_argument("--remote-server-auth-host")
        .help("Specify the remote server's IP address or hostname for authentication.")
        .default_value("1.1.1.1");
    args_.add_argument("--remote-server-auth-port")
        .help("Specify the port number for the remote server authentication. Set to 0 to use the default port.")
        .default_value(443)
        .scan<'i', int>();
}

bool CmdOptions::parse() noexcept
{
    try {
        args_.parse_args(argc_, argv_);
        return true;
    } catch (const std::runtime_error& err) {
        const std::string help = args_.help().str();
        spdlog::error("Argument parsing error: {}\n{}", err.what(), help);
    }
    return false;
}

std::string CmdOptions::getServerCrt() const
{
    return args_.get<std::string>("--server-crt");
}

std::string CmdOptions::getServerKey() const
{
    return args_.get<std::string>("--server-key");
}

std::string CmdOptions::getServerPub() const
{
    return args_.get<std::string>("--server-pub");
}

std::string CmdOptions::getOutNetworkInterface() const
{
    return args_.get<std::string>("--out-network-interface");
}

int CmdOptions::getServerPort() const
{
    return args_.get<int>("--server-port");
}

std::string CmdOptions::getTunInterfaceName() const
{
    return args_.get<std::string>("--tun-interface-name");
}

pcpp::IPv4Address CmdOptions::getTunInterfaceIPv4() const
{
    return pcpp::IPv4Address(
        args_.get<std::string>("--tun-interface-ip")
    );
}

pcpp::IPv4Address CmdOptions::getTunInterfaceNetworkIPv4Address() const
{
    return pcpp::IPv4Address(
        args_.get<std::string>("--tun-interface-network-address")
    );
}

int CmdOptions::getTunInterfaceNetworkIPv4Mask() const
{
    return args_.get<int>("--tun-interface-network-mask");
}


pcpp::IPv6Address CmdOptions::getTunInterfaceIPv6() const
{
    return pcpp::IPv6Address(
            args_.get<std::string>("--tun-interface-ipv6")
    );
}

pcpp::IPv6Address CmdOptions::getTunInterfaceNetworkIPv6Address() const
{
    return pcpp::IPv6Address(
            args_.get<std::string>("--tun-interface-network-ipv6-address")
    );
}

int CmdOptions::getTunInterfaceNetworkIPv6Mask() const
{
    return args_.get<int>("--tun-interface-network-ipv6-mask");
}


std::string CmdOptions::getUserFile() const
{
    return args_.get<std::string>("--userfile");
}

bool CmdOptions::useHttps() const
{
    return parseBoolean(args_.get<std::string>("--use-https"));
}

bool CmdOptions::disableBittorrent() const
{
    return parseBoolean(args_.get<std::string>("--disable-bittorrent"));
}

std::string CmdOptions::getPrometheusAccessKey() const
{
    return args_.get<std::string>("--prometheus-access-key");
}

bool CmdOptions::useRemoteServerAuth() const {
    return parseBoolean(args_.get<std::string>("--use-remote-server-auth"));
}

std::string CmdOptions::getRemoteServerAuthHost() const {
    return args_.get<std::string>("--remote-server-auth-host");
}

int CmdOptions::getRemoteServerAuthPort() const {
    return args_.get<int>("--remote-server-auth-port");
}
