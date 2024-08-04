#pragma once

#include <string>
#include <functional>

#include <hv/WebSocketServer.h>

#include <common/user/manager.h>
#include <common/jwt_token/token_manager.h>


namespace fptn::web
{
    class HttpServer final
    {
    public:
        HttpServer(
            const fptn::common::user::UserManagerSPtr& userManager,
            const fptn::common::jwt_token::TokenManagerSPtr& tokenManager
        );
        ~HttpServer() = default;
        hv::HttpService* getService();
    private:
        int onHomeHandle(HttpRequest* req, HttpResponse* resp) noexcept;
        int onLoginHandle(HttpRequest* req, HttpResponse* resp) noexcept;
    private:
        const std::string urlHome_="/";
        const std::string urlLogin_="/api/v1/login";

        fptn::common::user::UserManagerSPtr userManager_;
        fptn::common::jwt_token::TokenManagerSPtr tokenManager_;
        hv::HttpService http_;
    };
}
