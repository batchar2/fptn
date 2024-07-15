#pragma once

#include <string>
#include <iostream>
#include <functional>

#include <glog/logging.h>
#include <hv/WebSocketServer.h>


namespace fptn::web
{
    class http final
    {
    public:
        http();
        ~http() = default;
        hv::HttpService* get_service();
    private:
        int on_home_handle(HttpRequest* req, HttpResponse* resp) noexcept;
        int on_login_handle(HttpRequest* req, HttpResponse* resp) noexcept;
    private:
        const std::string home_uri_="/";
        const std::string login_uri_="/api/v1/login";
        hv::HttpService http_;
    };
}