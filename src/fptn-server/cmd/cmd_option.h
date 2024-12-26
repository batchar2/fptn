#pragma once

#include <string>

#include <argparse/argparse.hpp>
#include <pcapplusplus/IpAddress.h>


namespace fptn::cmd
{
    class CmdOptions
    {
    public:
        explicit CmdOptions(int argc, char* argv[]);
        bool parse() noexcept;
    public:
        /* options */
        std::string getServerCrt() const;
        std::string getServerKey() const;
        std::string getServerPub() const;
        std::string getOutNetworkInterface() const;
        int getServerPort() const;

        std::string getTunInterfaceName() const;
        /* IPv4 */
        pcpp::IPv4Address getTunInterfaceIPv4() const;
        pcpp::IPv4Address getTunInterfaceNetworkIPv4Address() const;
        int getTunInterfaceNetworkIPv4Mask() const;
        /* IPv6 */
        pcpp::IPv6Address getTunInterfaceIPv6() const;
        pcpp::IPv6Address getTunInterfaceNetworkIPv6Address() const;
        int getTunInterfaceNetworkIPv6Mask() const;

        std::string getUserFile() const;
        bool useHttps() const;
        bool disableBittorrent() const;
        std::string getPrometheusAccessKey() const;

        bool useRemoteServerAuth() const;
        std::string getRemoteServerAuthHost() const;
        int getRemoteServerAuthPort() const;
    private:
        int argc_;
        char** argv_;
        argparse::ArgumentParser args_;
    };

    using CmdOptionsSPtr = std::shared_ptr<CmdOptions>;
}
