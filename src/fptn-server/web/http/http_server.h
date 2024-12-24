#pragma once

#include <string>
#include <functional>

#include <hv/WebSocketServer.h>
#include <pcapplusplus/IpAddress.h>

#include <common/jwt_token/token_manager.h>

#include "user/user_manager.h"
#include "statistic/metrics.h"


namespace fptn::web
{
    class HttpServer final
    {
    public:
        HttpServer(
            const fptn::user::UserManagerSPtr& userManager,
            const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
            const fptn::statistic::MetricsSPtr& prometheus,
            const std::string& prometheusAccessKey,
            const pcpp::IPv4Address& dnsServer
        );
        ~HttpServer() = default;
        hv::HttpService* getService();
    private:
        int onDnsHandle(HttpRequest* req, HttpResponse* resp) noexcept;
        int onHomeHandle(HttpRequest* req, HttpResponse* resp) noexcept;
        int onStatistics(HttpRequest* req, HttpResponse* resp) noexcept;
        int onLoginHandle(HttpRequest* req, HttpResponse* resp) noexcept;
        int onTestFileBin(HttpRequest* req, HttpResponse* resp) noexcept;
    private:
        const std::string urlHome_="/";
        const std::string urlDns_="/api/v1/dns";
        const std::string urlLogin_="/api/v1/login";
        const std::string urlMetrics_="/api/v1/metrics";
        const std::string urlTestFileBin_="/api/v1/test/file.bin";

        fptn::user::UserManagerSPtr userManager_;
        fptn::common::jwt_token::TokenManagerSPtr tokenManager_;
        fptn::statistic::MetricsSPtr prometheus_;

        pcpp::IPv4Address dnsServer_;
        hv::HttpService http_;
    };


    inline void setHttpHeaders(HttpResponse* resp, const std::string& contentType) noexcept
    {
        resp->SetHeader("Server", "nginx/1.24.0");
        resp->SetHeader("Content-Type", contentType);
        resp->SetHeader("Connection", "keep-alive");
        resp->SetHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        resp->SetHeader("Pragma", "no-cache");
        resp->SetHeader("Expires", "Fri, 07 Jun 1974 04:00:00 GMT");
        resp->SetHeader("x-bitrix-composite", "Cache (200)");
    }
}
