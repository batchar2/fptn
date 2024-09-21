#include <future>
#include <variant>

#include <fmt/format.h>
#include <hv/requests.h>
#include <glog/logging.h>

#include <openssl/ssl.h>

#include <common/protobuf/protocol.h>

#include "system/iptables.h"

#include "websocket_client.h"


/* Google Chrome 56, Windows 10, April 2017 */
static const char *chromeCiphers = "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-CBC-SHA:"
    "ECDHE-RSA-AES256-CBC-SHA:"
    "RSA-AES128-GCM-SHA256:"
    "RSA-AES256-GCM-SHA384:"
    "RSA-AES128-CBC-SHA:"
    "RSA-AES256-CBC-SHA:"
    "RSA-3DES-EDE-CBC-SHA";


using namespace fptn::http;


WebSocketClient::WebSocketClient(
    const std::string& vpnServerIP, 
    int vpnServerPort,
    const std::string& tunInterfaceAddress,
    bool useSsl,
    const NewIPPacketCallback& newIPPktCallback 
)
    :
        connection_(nullptr),
        running_(false),
        vpnServerIP_(vpnServerIP),
        vpnServerPort_(vpnServerPort),
        token_(""),
        tunInterfaceAddress_(tunInterfaceAddress),
        newIPPktCallback_(newIPPktCallback)
{
    // Set logging
    // ws_.set_access_channels(websocketpp::log::alevel::all);
    ws_.set_access_channels(websocketpp::log::alevel::none);

    ws_.clear_access_channels(websocketpp::log::alevel::frame_payload);
    ws_.set_open_handshake_timeout(10000);
    ws_.set_close_handshake_timeout(10000);

    ws_.init_asio();
    ws_.set_tls_init_handler(std::bind(&WebSocketClient::onTlsInit, this));
    ws_.set_message_handler(
        std::bind(
            &WebSocketClient::onMessage,
            this,
            std::placeholders::_1,
            std::placeholders::_2
        )
    );
}

bool WebSocketClient::login(const std::string& username, const std::string& password) noexcept
{
    httplib::SSLClient cli(vpnServerIP_, vpnServerPort_);
    {
        cli.enable_server_certificate_verification(false); // NEED TO FIX
        cli.set_connection_timeout(0, 300000); // 300 milliseconds
        cli.set_read_timeout(3, 0); // 3 seconds
        cli.set_write_timeout(3, 0); // 3 seconds
        if (SSL_CTX_set_cipher_list(cli.ssl_context(), chromeCiphers) != 1) {
            LOG(ERROR) << "Failed to set cipher list" << std::endl;
            return false;
        }
    }

    const std::string request = fmt::format(R"({{ "username": "{}", "password": "{}" }})", username, password);
    if (auto res = cli.Post("/api/v1/login", getRealBrowserHeaders(), request, "application/json" )){
        if (res->status == httplib::StatusCode::OK_200) {
            try {
                auto response = nlohmann::json::parse(res->body);
                if (response.contains("access_token")) {
                    token_ = response["access_token"];
                    LOG(INFO) << "Login successful.";
                    return true;
                } else {
                    LOG(ERROR) << "Error: Access token not found in the response. Check your conection";
                }
            } catch (const nlohmann::json::parse_error& e) {
                LOG(ERROR) << "Error parsing JSON response: " << e.what() << std::endl << res->body;
            }
        } else {
            LOG(ERROR) << "Error: " << res->body;
        }
    } else {
        LOG(ERROR) << "Error: Request failed or response is null.";
    }
    return false;
}

std::string WebSocketClient::getDns() noexcept
{
    httplib::SSLClient cli(vpnServerIP_, vpnServerPort_);
    {
        cli.enable_server_certificate_verification(false); // NEED TO FIX
        cli.set_connection_timeout(0, 300000); // 300 milliseconds
        cli.set_read_timeout(3, 0); // 3 seconds
        cli.set_write_timeout(3, 0); // 3 seconds
        if (SSL_CTX_set_cipher_list(cli.ssl_context(), chromeCiphers) != 1) {
            LOG(ERROR) << "Failed to set cipher list" << std::endl;
            return {};
        }
    }
    if (auto res = cli.Get("/api/v1/dns", getRealBrowserHeaders())) {
        if (res->status == httplib::StatusCode::OK_200) {
            try {
                auto response = nlohmann::json::parse(res->body);
                if (response.contains("dns")) {
                    const std::string dnsServer = response["dns"];
                    return dnsServer;
                } else {
                    LOG(ERROR) << "Error: dns not found in the response. Check your conection";
                }
            } catch (const nlohmann::json::parse_error& e) {
                LOG(ERROR) << "Error parsing JSON response: " << e.what() << std::endl << res->body;
            }
        } else {
            LOG(ERROR) << "Error: " << res->body;
        }
    } else {
        LOG(ERROR) << "Error: Request failed or response is null.";
    }
    return {};
}

AsioSslContextPtr WebSocketClient::onTlsInit() noexcept
{
    LOG(INFO) << "INIT TLS";
    AsioSslContextPtr ctx = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);
    try {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::single_dh_use |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3
        );
        if (SSL_CTX_set_cipher_list(ctx->native_handle(), chromeCiphers) != 1) {
            LOG(ERROR) << "Failed to set cipher list" << std::endl;
        }
        ctx->set_verify_mode(boost::asio::ssl::verify_none);
        // to trust
        // ctx->load_verify_file("path_to_your_cert.pem");
        // ctx->set_verify_mode(boost::asio::ssl::verify_peer);
    } catch (std::exception &e) {
        LOG(ERROR) << "Error in context pointer: " << e.what() << std::endl;
    }
    return ctx;
}

void WebSocketClient::onMessage(websocketpp::connection_hdl hdl, AsioMessagePtr msg) noexcept
{
    try {
        std::string rawIpPacket = fptn::common::protobuf::protocol::getPayload(msg->get_payload());
        auto packet = fptn::common::network::IPPacket::parse(std::move(rawIpPacket));
        if (packet != nullptr && newIPPktCallback_) {
            newIPPktCallback_(std::move(packet));
        }
    } catch (const fptn::common::protobuf::protocol::ProcessingError &err) {
        LOG(ERROR) << "Processing error: " << err.what();
        //const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_DEFAULT);
    } catch (const fptn::common::protobuf::protocol::MessageError &err) {
        LOG(ERROR) << "Message error: " << err.what();
    } catch (const fptn::common::protobuf::protocol::UnsoportedProtocolVersion &err) {
        LOG(ERROR) << "Unsupported protocol version: " << err.what();
        //const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_WRONG_VERSION);
    } catch(...) {
        LOG(ERROR) << "Unexpected error: ";
    }
}

void WebSocketClient::setNewIPPacketCallback(const NewIPPacketCallback& callback) noexcept
{
    newIPPktCallback_ = callback;
}

bool WebSocketClient::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    try {
        const std::string msg = fptn::common::protobuf::protocol::createPacket(
                std::move(packet)
        );
        if (connection_ && running_) {
            std::unique_lock<std::mutex> lock(mutex_);
            websocketpp::lib::error_code ec  = connection_->send(msg, websocketpp::frame::opcode::binary);
            if (ec) {
                return false;
            }
            return true;
        }
    } catch (const std::runtime_error &err) {
        LOG(ERROR) << "Send error: " << err.what();
    } catch (const std::exception &e) {
        LOG(ERROR) << "Exception occurred: " << e.what();
    }
    return false;
}

void WebSocketClient::run() noexcept
{
    const std::string url = fmt::format("wss://{}:{}/fptn", vpnServerIP_, vpnServerPort_);
    while (running_)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        {
            /* init connection */
            std::unique_lock<std::mutex> lock(mutex_);

            websocketpp::lib::error_code ec;
            connection_ = ws_.get_connection(url, ec);
            if (ec) {
                LOG(ERROR) << "Could not create connection because: " << ec.message() << std::endl;
            }
            connection_->append_header("Authorization", "Bearer " + token_);
            connection_->append_header("ClientIP", tunInterfaceAddress_);
        }
        {
            /* loop */
            ws_.connect(connection_);
            ws_.run();
        }
        {
            /* deinit */
            std::unique_lock<std::mutex> lock(mutex_);

            connection_.reset();
            ws_.reset();
        }
        LOG(ERROR) << "Connection closed";
    }
}

bool WebSocketClient::start() noexcept
{
    running_ = true;
    th_ = std::thread(&WebSocketClient::run, this);
    return th_.joinable();
}

bool WebSocketClient::stop() noexcept
{
    if (running_ && th_.joinable()) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (connection_) {
                connection_.reset();
            }
        }
        running_ = false;
        if (!ws_.stopped()) {
            ws_.stop();
        }
        th_.join();
        return true;
    }
    return false;
}

httplib::Headers WebSocketClient::getRealBrowserHeaders() noexcept
{
    /* Just to ensure that FPTN is as similar to a web browser as possible. */
#ifdef __linux__
    // firefox ubuntu arm
    return {
        {"Host", (vpnServerPort_ == 443 ? vpnServerIP_ : fmt::format("{}:{}", vpnServerIP_, vpnServerPort_))},
        {"User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"},
        {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"},
        {"Accept-Language", "en-US,en;q=0.5"},
        {"Accept-Encoding", "gzip, deflate, br, zstd"},
        {"Referer", "https://www.google.com/"},
        {"upgrade-insecure-requests", "1"},
        {"sec-fetch-dest", "document"},
        {"sec-fetch-mode", "navigate"},
        {"sec-fetch-site", "cross-site"},
        {"sec-fetch-user", "?1"},
        {"priority", "u=0, i"},
        {"te", "trailers"}
    };
#elif __APPLE__
    // apple silicon chrome
    return {
        {"Host", (vpnServerPort_ == 443 ? vpnServerIP_ : fmt::format("{}:{}", vpnServerIP_, vpnServerPort_))},
        {"sec-ch-ua", R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
        {"sec-ch-ua-platform", "\"macOS\""},
        {"sec-ch-ua-mobile", "?0"},
        {"upgrade-insecure-requests", "1"},
        {"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
        {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
        {"sec-fetch-site", "none"},
        {"sec-fetch-mode", "no-cors"},
        {"sec-fetch-dest", "empty"},
        {"Referer", "https://www.google.com/"},
        {"Accept-Encoding", "gzip, deflate, br"},
        {"Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"},
        {"priority", "u=4, i"}
    };
#elif _WIN32
    // chrome windows amd64
    return {
        {"Host", (vpnServerPort_ == 443 ? vpnServerIP_ : fmt::format("{}:{}", vpnServerIP_, vpnServerPort_))},
        {"sec-ch-ua", R"("Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128")"},
        {"sec-ch-ua-mobile", "?0"},
        {"sec-ch-ua-platform", "\"Windows\""},
        {"upgrade-insecure-requests", "1"},
        {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"},
        {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
        {"sec-fetch-site", "cross-site"},
        {"sec-fetch-mode", "navigate"},
        {"sec-fetch-user", "?1"},
        {"sec-fetch-dest", "document"},
        {"Referer", "https://www.google.com/"},
        {"Accept-Encoding", "gzip, deflate, br, zstd"},
        {"Accept-Language", "en-US,en;q=0.9,ru;q=0.8"},
        {"priority", "u=0, i"}
    };
#else
    #error "Unsupported system!"
#endif
}