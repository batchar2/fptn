#pragma once

#include <string>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <common/client_id.h>
#include <common/network/ip_packet.h>


namespace fptn::web
{
    namespace http {
        using request = boost::beast::http::request<boost::beast::http::string_body>;
        using response = boost::beast::http::response<boost::beast::http::string_body>;
    }
    using ApiHandle = std::function<int(const http::request &req, http::response &resp)>;

    using ApiHandleMap = std::unordered_map<std::string, ApiHandle>;

    inline std::string getApiKey(const std::string& url, const std::string& method)
    {
        return method + " " + url;
    }

    inline void addApiHandle(ApiHandleMap& m, const std::string& url, const std::string& method, const ApiHandle& handle) noexcept
    {
        const std::string key = getApiKey(url, method);
        m[key] = handle;
    }

    inline ApiHandle getApiHandle(const ApiHandleMap& m, const std::string& url, const std::string& method) noexcept
    {
        const std::string key = getApiKey(url, method);
        auto it = m.find(key);
        if (it != m.end()) {
            return it->second;
        }
        return nullptr;
    }

    class Session;
    using WebSocketOpenConnectionCallback = std::function<bool(
        fptn::ClientID clientId,
        const pcpp::IPv4Address& clientIP,
        const pcpp::IPv4Address& clientVpnIPv4,
        const pcpp::IPv6Address& clientVpnIPv6,
        std::shared_ptr<Session> session,
        const std::string& url,
        const std::string& accessToken
    )>;
    using WebSocketNewIPPacketCallback = std::function<void(fptn::common::network::IPPacketPtr packet)>;
    using WebSocketCloseConnectionCallback = std::function<void(fptn::ClientID clientId)>;
}
