#include <fmt/format.h>
#include <openssl/ssl.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

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


static int onSetServerNameCallback(SSL* ssl, int* ad, void* arg) noexcept;


WebSocketClient::WebSocketClient(
    const pcpp::IPv4Address& vpnServerIP,
    int vpnServerPort,
    const pcpp::IPv4Address& tunInterfaceAddressIPv4,
    const pcpp::IPv6Address& tunInterfaceAddressIPv6,
    bool useSsl,
    const NewIPPacketCallback& newIPPktCallback,
    const std::string& sni
)
    :
        connection_(nullptr),
        running_(false),
        vpnServerIP_(vpnServerIP),
        vpnServerPort_(vpnServerPort),
        tunInterfaceAddressIPv4_(tunInterfaceAddressIPv4),
        tunInterfaceAddressIPv6_(tunInterfaceAddressIPv6),
        newIPPktCallback_(newIPPktCallback),
        sni_(sni)
{
    (void)useSsl;
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
    ws_.set_socket_init_handler(
        websocketpp::lib::bind(
            &WebSocketClient::onHandleSocketInit,
            this,
            websocketpp::lib::placeholders::_1,
            websocketpp::lib::placeholders::_2
        )
    );
}

void WebSocketClient::onHandleSocketInit(websocketpp::connection_hdl hdl, AsioSocketType& socket) noexcept
{
    std::cerr << "+++" << sni_ << std::endl;
    (void)hdl;
    if (!SSL_set_tlsext_host_name(reinterpret_cast<SSL*>(socket.native_handle()), sni_.c_str())) {
        spdlog::info("Failed to set SNI host name... this might go awry");
    }
}



bool WebSocketClient::setupSni(SSL_CTX* ctx) noexcept
{
    if (SSL_CTX_set_cipher_list(ctx, chromeCiphers) != 1) {
        spdlog::error("Failed to set cipher list");
        return false;
    }
    if (SSL_CTX_set_tlsext_servername_callback(ctx, &onSetServerNameCallback) != 1) {
        spdlog::error("Failed to set SNI callback");
        return false;
    }
    SSL_CTX_set_tlsext_servername_arg(ctx, this);
    return true;
}

bool WebSocketClient::setupHttplibSSL(httplib::SSLClient& cli, int timeoutSec) noexcept
{
    // set timeout
    cli.enable_server_certificate_verification(false); // NEED TO FIX
    cli.set_connection_timeout(timeoutSec, 0);
    cli.set_read_timeout(timeoutSec, 0);
    cli.set_write_timeout(timeoutSec, 0);

    // setup SNI
    return setupSni(cli.ssl_context());
}

int onSetServerNameCallback(SSL* ssl, int* ad, void* arg) noexcept
{
    (void)ad;
    std::cerr << "+1" << std::endl;
    if (!ssl || !arg) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    std::cerr << "+2" << std::endl;
    const auto* client = static_cast<WebSocketClient*>(arg);
    const std::string& sni = client->sni();
    if (!sni.empty()) {
        std::cerr << "+3>" << sni << std::endl;

        if (SSL_set_tlsext_host_name(ssl, sni.c_str()) != 1) {
            spdlog::error("Failed to set SNI: {}", ERR_reason_error_string(ERR_get_error()));
        }

    }
    std::cerr << "+4" << std::endl;
    return SSL_TLSEXT_ERR_OK;
}

const std::string& WebSocketClient::sni() const noexcept
{
    return sni_;
}

bool WebSocketClient::login(const std::string& username, const std::string& password) noexcept
{
    httplib::SSLClient cli(vpnServerIP_.toString(), vpnServerPort_);
    if (!setupHttplibSSL(cli)) {
        return false;
    }
    spdlog::info("Login. Connect to {}:{}", vpnServerIP_.toString(), vpnServerPort_);
    const std::string request = fmt::format(R"({{ "username": "{}", "password": "{}" }})", username, password);
    if (auto res = cli.Post("/api/v1/login", getRealBrowserHeaders(), request, "application/json")) {
        if (res->status == httplib::StatusCode::OK_200) {
            try {
                auto response = nlohmann::json::parse(res->body);
                if (response.contains("access_token")) {
                    token_ = response["access_token"];
                    spdlog::info("Login successful");
                    return true;
                } else {
                    spdlog::error("Error: Access token not found in the response. Check your conection");
                }
            } catch (const nlohmann::json::parse_error& e) {
                spdlog::error("Error parsing JSON response: {}  {}", e.what(), res->body);
            }
        } else {
            spdlog::error("Error: {}", res->body);
        }
    } else {
        auto error = res.error();
        spdlog::error("Error: Request failed or response is null. {}", to_string(error));
    }
    return false;
}

std::pair<pcpp::IPv4Address, pcpp::IPv6Address> WebSocketClient::getDns() noexcept
{
    spdlog::info("DNS. Connect to {}:{}", vpnServerIP_.toString(), vpnServerPort_);
    httplib::SSLClient cli(vpnServerIP_.toString(), vpnServerPort_);
    if (setupHttplibSSL(cli)) {
        if (auto res = cli.Get("/api/v1/dns", getRealBrowserHeaders())) {
            if (res->status == httplib::StatusCode::OK_200) {
                try {
                    auto response = nlohmann::json::parse(res->body);
                    if (response.contains("dns")) {
                        const std::string dnsServerIPv4 = response["dns"];
                        const std::string dnsServerIPv6 = (
                                response.contains("dns_ipv6")
                                ? response["dns_ipv6"]
                                : FPTN_SERVER_DEFAULT_ADDRESS_IP6 // default for old servers
                        );
                        return {pcpp::IPv4Address(dnsServerIPv4), pcpp::IPv6Address(dnsServerIPv6)};
                    } else {
                        spdlog::error("Error: dns not found in the response. Check your conection");
                    }
                } catch (const nlohmann::json::parse_error &e) {
                    spdlog::error("Error parsing JSON response: {} {}", e.what(), res->body);
                }
            } else {
                spdlog::error("Error: {}", res->body);
            }
        } else {
            spdlog::error("Error: Request failed or response is null.");
        }
    }
    return {pcpp::IPv4Address("0.0.0.0"), pcpp::IPv6Address("")};
}

AsioSslContextPtr WebSocketClient::onTlsInit() noexcept
{
    AsioSslContextPtr ctx = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::sslv23);
    try {
        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                         boost::asio::ssl::context::single_dh_use |
                         boost::asio::ssl::context::no_sslv2 |
                         boost::asio::ssl::context::no_sslv3
        );
//        if (!SSL_set_tlsext_host_name(ctx->native_handle(), sni_.c_str())) {
//            spdlog::error("Failed to set SNI");
//        }
//        if (!SSL_set_tlsext_host_name(ws_.next_layer().native_handle(), server_.host.c_str()))
//        {
//            LOG(ERROR, LOG_TAG) << "Failed to set SNI Hostname\n";
//            return boost::system::error_code(static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category());
//        }
        std::cerr << "SETUP SNI" << std::endl;
//        if (!SSL_set_tlsext_host_name(ctx->native_handle(), sni_.c_str())) {
//            spdlog::error("Failed to set SNI");
//        }
        if (setupSni(ctx->native_handle()))
        {
            if (SSL_CTX_set_cipher_list(ctx->native_handle(), chromeCiphers) != 1) {
                spdlog::error("Failed to set cipher list");
            }
            ctx->set_verify_mode(boost::asio::ssl::verify_none);
            // to trust
            // ctx->load_verify_file("path_to_your_cert.pem");
            // ctx->set_verify_mode(boost::asio::ssl::verify_peer);
        }
    } catch (std::exception &e) {
        spdlog::error("Error in context pointer: {}", e.what());
    }
    return ctx;
}

void WebSocketClient::onMessage(websocketpp::connection_hdl hdl, AsioMessagePtr msg) noexcept
{
    (void)hdl;
    try {
        std::string rawIpPacket = fptn::common::protobuf::protocol::getPayload(msg->get_payload());
        auto packet = fptn::common::network::IPPacket::parse(std::move(rawIpPacket));
        if (packet != nullptr && newIPPktCallback_) {
            newIPPktCallback_(std::move(packet));
        }
    } catch (const fptn::common::protobuf::protocol::ProcessingError &err) {
        spdlog::error("Processing error: {}", err.what());
        //const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_DEFAULT);
    } catch (const fptn::common::protobuf::protocol::MessageError &err) {
        spdlog::error("Message error: {}", err.what());
    } catch (const fptn::common::protobuf::protocol::UnsoportedProtocolVersion &err) {
        spdlog::error("Unsupported protocol version: {}", err.what());
        //const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_WRONG_VERSION);
    } catch(...) {
        spdlog::error("Unexpected error!");
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
        spdlog::error("Send error: {}", err.what());
    } catch (const std::exception &e) {
        spdlog::error("Exception occurred: {}", e.what());
    }
    return false;
}

void WebSocketClient::run() noexcept
{
    const std::string url = fmt::format("wss://{}:{}/fptn", vpnServerIP_.toString(), vpnServerPort_);
    while (running_)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        {
            /* init connection */
            std::unique_lock<std::mutex> lock(mutex_);

            websocketpp::lib::error_code ec;
            connection_ = ws_.get_connection(url, ec);
            if (ec) {
                spdlog::error("Could not create connection because: {}", ec.message());
            }
            /* adding a real headers */
            httplib::Headers headers = getRealBrowserHeaders();
            for (const auto& [header_name, header_value] : headers) {
                connection_->append_header(header_name, header_value);
            }
            /* need to provide auth and local vpn address */
            connection_->append_header("Authorization", "Bearer " + token_);
            connection_->append_header("ClientIP", tunInterfaceAddressIPv4_.toString());
            connection_->append_header("ClientIPv6", tunInterfaceAddressIPv6_.toString());
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
        spdlog::error("Connection closed");
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
        {"Host", (vpnServerPort_ == 443 ? vpnServerIP_.toString() : fmt::format("{}:{}", vpnServerIP_.toString(), vpnServerPort_))},
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
        {"Host", (vpnServerPort_ == 443 ? vpnServerIP_.toString() : fmt::format("{}:{}", vpnServerIP_.toString(), vpnServerPort_))},
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
        {"Host", (vpnServerPort_ == 443 ? vpnServerIP_.toString() : fmt::format("{}:{}", vpnServerIP_.toString(), vpnServerPort_))},
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

//bool WebSocketClient::setupHttplibSSL(httplib::SSLClient& cli, int timeoutSec) noexcept
//{
//    SSL_CTX* ctx = cli.ssl_context();
//    if (!ctx) {
//        spdlog::error("Failed to get SSL context");
//        return false;
//    }
//
//    // Store SNI for reference
////    sni_ = sni;
//
//    // Set TLS options
//    cli.enable_server_certificate_verification(true);
//    cli.set_connection_timeout(timeoutSec, 0);
//    cli.set_read_timeout(timeoutSec, 0);
//    cli.set_write_timeout(timeoutSec, 0);
//
//    // **Directly set SNI before connection starts**
//    if (SSL_CTX_set_tlsext_servername_callback(ctx, nullptr) != 1) {
//        spdlog::error("Failed to disable SNI callback (not needed)");
//    }
//
//    SSL* ssl = SSL_new(ctx);
//    if (!ssl) {
//        spdlog::error("Failed to create SSL structure");
//        return false;
//    }
//
//    if (SSL_set_tlsext_host_name(ssl, sni_.c_str()) != 1) {
//        spdlog::error("Failed to set SNI to {}", sni_);
//        SSL_free(ssl);
//        return false;
//    }
//
//    spdlog::info("SNI successfully set to {}", sni_);
//
//    SSL_free(ssl);  // Cleanup temporary SSL structure
//    return true;
//}