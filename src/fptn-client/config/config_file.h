#pragma once

#include <string>
#include <vector>


namespace fptn::config
{
    class ConfigFile final
    {
    public:
        struct Server
        {
            std::string name;
            std::string host;
            int port;
            bool isUsing;

            // FIX USING FOR CLI
            std::string username;
            std::string password;
            std::string serviceName;
        };
    public:
        explicit ConfigFile(std::string sni);
        explicit ConfigFile(std::string token, std::string sni);

        bool parse();
        Server findFastestServer() const;
        bool addServer(const Server &s);
    public:
        int getVersion() const noexcept;
        std::string getServiceName() const noexcept;
        std::string getUsername() const noexcept;
        std::string getPassword() const  noexcept;
        std::vector<Server> getServers() const noexcept;
    public:
        std::uint64_t getDownloadTimeMs(const Server& server, int timeout = 4) const noexcept;
    private:
        const std::string token_;
        const std::string sni_;

        int version_;
        std::string serviceName_;
        std::string username_;
        std::string password_;
        std::vector<Server> servers_;
    };
}