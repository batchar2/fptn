#pragma once

#include <string>
#include <vector>
#include <filesystem>


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
        };
    public:
        ConfigFile() = default;
        explicit ConfigFile(const std::filesystem::path& path);
        bool parse();
        Server findFastestServer() const;
        bool addServer(const Server &s);
    public:
        int getVersion() const noexcept;
        std::string getServiceName() const noexcept;
        std::string getUsername() const noexcept;
        std::string getPassword() const  noexcept;
        std::vector<Server> getServers() const noexcept;
    private:
        std::uint64_t getDownloadTimeMs(const Server& server) const noexcept;
    private:
        std::filesystem::path path_;
        int version_;
        std::string serviceName_;
        std::string username_;
        std::string password_;
        std::vector<Server> servers_;
    };
}