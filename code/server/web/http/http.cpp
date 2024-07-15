#include "http.h"

using namespace fptn::web;

static const std::string html_home_page = R"HTML(<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FOPN: Current Time</title>
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


http::http()
{
    using namespace std::placeholders;
    http_.GET(home_uri_.c_str(), std::bind(&http::on_home_handle, this, _1, _2));
    http_.POST(login_uri_.c_str(), std::bind(&http::on_login_handle, this, _1, _2));
}


hv::HttpService* http::get_service()
{
    return &http_;
}


int http::on_home_handle(HttpRequest* req, HttpResponse* resp) noexcept
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


int http::on_login_handle(HttpRequest* req, HttpResponse* resp) noexcept
{
    (void)req;
    return resp->Json(http_.Paths());
}
