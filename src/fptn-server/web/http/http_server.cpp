#include <fmt/format.h>
#include <glog/logging.h>

#include "http_server.h"

using namespace fptn::web;


static const std::string html_home_page = R"HTML(<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FPTN: Current Time</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f0f0f0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                text-align: center;
                padding: 20px;
                background-color: #fff;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                width: 80%;
                max-width: 600px;
                margin: auto;
            }
            #time {
                font-size: 4em;
                margin-bottom: 20px;
            }
            button {
                padding: 10px 20px;
                font-size: 1em;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                transition: background-color 0.3s ease;
            }
            button:hover {
                background-color: #45a049;
            }
            html, body {
                height: 100%;
            }
            body {
                display: flex;
                justify-content: center;
                align-items: center;
                background-color: #ccc;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div id="time">00:00:00</div>
            <button onclick="updateTime()">Update</button>
        </div>
        <script>
            function updateTime() {
                const now = new Date();
                const hours = String(now.getHours()).padStart(2, '0');
                const minutes = String(now.getMinutes()).padStart(2, '0');
                const seconds = String(now.getSeconds()).padStart(2, '0');
                const timeString = `${hours}:${minutes}:${seconds}`;
                document.getElementById('time').textContent = timeString;
            }
            setInterval(updateTime, 1000);
        </script>
    </body>
</html>
)HTML";


HttpServer::HttpServer(
        const fptn::common::user::UserManagerSPtr& userManager,
        const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
        const fptn::statistic::MetricsSPtr& prometheus,
        const std::string& prometheusAccessKey,
        const pcpp::IPv4Address& dnsServer
)
    : 
        userManager_(userManager),
        tokenManager_(tokenManager),
        prometheus_(prometheus),
        dnsServer_(dnsServer)
{
    using namespace std::placeholders;
    http_.GET(urlHome_.c_str(), std::bind(&HttpServer::onHomeHandle, this, _1, _2));
    http_.GET(urlDns_.c_str(), std::bind(&HttpServer::onDnsHandle, this, _1, _2));


    http_.POST(urlLogin_.c_str(), std::bind(&HttpServer::onLoginHandle, this, _1, _2));
    // prometheus statistics
    if (!prometheusAccessKey.empty()) {
        // Construct the URL for accessing Prometheus statistics by appending the access key
        const std::string metrics = urlMetrics_ + '/' + prometheusAccessKey;
        http_.GET(metrics.c_str(), std::bind(&HttpServer::onStatistics, this, _1, _2));
    }
}

hv::HttpService* HttpServer::getService()
{
    return &http_;
}

int HttpServer::onHomeHandle(HttpRequest* req, HttpResponse* resp) noexcept
{
    (void)req;
    resp->SetHeader("Server", "nginx/1.24.0");
    resp->SetHeader("Content-Type", "text/html; charset=utf-8");
    resp->SetHeader("Connection", "keep-alive");
    resp->SetHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    resp->SetHeader("Pragma", "no-cache");
    resp->SetHeader("Expires", "Fri, 07 Jun 1974 04:00:00 GMT");
    resp->SetHeader("x-bitrix-composite", "Cache (200)");
    return resp->String(html_home_page);
}

int HttpServer::onDnsHandle(HttpRequest* req, HttpResponse* resp) noexcept
{
    resp->SetHeader("Content-Type", "application/json; charset=utf-8");
    resp->String(
        fmt::format(R"({{"dns": "{}"}})", dnsServer_.toString())
    );
    return 200;
}

int HttpServer::onStatistics(HttpRequest* req, HttpResponse* resp) noexcept
{
    return resp->String(prometheus_->collect());
}

int HttpServer::onLoginHandle(HttpRequest* req, HttpResponse* resp) noexcept
{
    resp->SetHeader("Content-Type", "application/json; charset=utf-8");
    try {
        auto request = nlohmann::json::parse(req->Body());
        const auto username = request.at("username").get<std::string>();
        const auto password = request.at("password").get<std::string>();
        if (userManager_->authenticate(username, password) ) {
            LOG(INFO) << "Successful login for user " << username;
            const int bandwidthBit = userManager_->getUserBandwidthBit(username);
            const auto tokens = tokenManager_->generate(username, bandwidthBit);
            resp->String(
                fmt::format(
                    R"({{"access_token": "{}", "refresh_token": "{}"}})", 
                    tokens.first, 
                    tokens.second
                )
            );
            return 200;
        }
        LOG(WARNING) << "Wrong password for user: \"" << username << "\"";
        resp->String(R"({"status": "error", "message": "Invalid login or password."})");
        return 401;
    } catch (const nlohmann::json::exception& e) {
        LOG(ERROR) << "HTTP JSON AUTH ERROR: " << e.what();
        resp->String(R"({"status": "error", "message": "Invalid JSON format."})");
        return 400;
    } catch (const std::exception& e) {
        LOG(ERROR) << "HTTP AUTH ERROR: " << e.what();
        resp->String(R"({"status": "error", "message": "An unexpected error occurred."})");
        return 500;
    } catch(...) {
        LOG(ERROR) << "UNDEFINED SERVER ERROR";
        resp->String(R"({"status": "error", "message": "Undefined server error"})");
        return 501;
    }
    return 402;
}
