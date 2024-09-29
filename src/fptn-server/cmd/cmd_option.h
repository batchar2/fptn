#pragma once

#include <memory>

#include <glog/logging.h>
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
        pcpp::IPv4Address getTunInterfaceIP() const;
        pcpp::IPv4Address getTunInterfaceNetworkAddress() const;
        int getTunInterfaceNetworkMask() const;
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
