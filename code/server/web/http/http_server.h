#pragma once

#include <string>
#include <functional>

#include <hv/WebSocketServer.h>


namespace fptn::web
{
    class HttpServer final
    {
    public:
        HttpServer();
        ~HttpServer() = default;
        inline hv::HttpService* getService()
        {
            return &http_;
        }
    private:
        int onHomeHandle(HttpRequest* req, HttpResponse* resp) noexcept;
        int onLoginHandle(HttpRequest* req, HttpResponse* resp) noexcept;
    private:
        const std::string urlHome_="/";
        const std::string urlLogin_="/api/v1/login";
        hv::HttpService http_;
    };
}