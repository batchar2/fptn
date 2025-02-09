#include "session.h"

#include <atomic>
#include <spdlog/spdlog.h>
#include <boost/algorithm/string/replace.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/beast/core.hpp>

using namespace fptn::web;

static std::atomic<fptn::ClientID> CLIENT_ID = 0;

using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::use_awaitable;
namespace this_coro = boost::asio::this_coro;


Session::Session(boost::asio::ip::tcp::socket&& socket,
    boost::asio::ssl::context& ctx,
    const ApiHandleMap& apiHandles,
    WebSocketOpenConnectionCallback wsOpenCallback,
    WebSocketNewIPPacketCallback wsNewIPCallback,
    WebSocketCloseConnectionCallback wsCloseCallback
)
    :
        isRunning_(false),
        ws_(std::move(socket), ctx),
        apiHandles_(apiHandles),
        wsOpenCallback_(wsOpenCallback),
        wsNewIPCallback_(wsNewIPCallback),
        wsCloseCallback_(wsCloseCallback),
        isInitComplete_(false)
{
    try {
        boost::beast::get_lowest_layer(ws_).socket().set_option(
            boost::asio::ip::tcp::no_delay(true)
        ); // turn off the Nagle algorithm.

        ws_.text(false);
        ws_.binary(true); // Only binary
        ws_.auto_fragment(true); // FIXME NEED CHECK
        ws_.read_message_max(128 * 1024); // MaxSize (128 KB)
        ws_.set_option(
            boost::beast::websocket::stream_base::timeout::suggested(
                boost::beast::role_type::server
            )
        );
        ws_.set_option(
            boost::beast::websocket::stream_base::timeout{
                std::chrono::seconds(60), // Handshake timeout
                std::chrono::hours(24),   // Idle timeout
                true                      // Enable ping timeout
            }
        );
        boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::minutes(30));
        isInitComplete_ = true;
    } catch (boost::system::system_error& err) {
        spdlog::error("Session::init error: {}", err.what());
    } catch (const std::exception& e) {
        spdlog::error("Session::init prepare: {}", e.what());
    }
}

Session::~Session()
{
    close();
}

boost::asio::awaitable<void> Session::run() noexcept
{
    boost::system::error_code ec;
    boost::beast::flat_buffer buffer;
    boost::beast::http::request<boost::beast::http::string_body> request;

    // check init status
    if (!isInitComplete_) {
        spdlog::error("Session is not initialized. Closing session.");
        close();
        co_return;
    }

    // do handshake
    co_await ws_.next_layer().async_handshake(
        boost::asio::ssl::stream_base::server,
        boost::asio::redirect_error(boost::asio::use_awaitable, ec)
    );
    if (ec) {
        spdlog::error("Session handshake failed: {} ({})", ec.what(), ec.value());
        close();
        co_return;
    }
    isRunning_ = co_await processRequest();

    while(isRunning_) {
        try {
            // read
            co_await ws_.async_read(buffer, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec) {
                break;
            }
            // parse
            if (buffer.size() != 0) {
                std::string rawdata = boost::beast::buffers_to_string(buffer.data());
                std::string rawip = fptn::common::protobuf::protocol::getPayload(std::move(rawdata));
                auto packet = fptn::common::network::IPPacket::parse(std::move(rawip), clientId_);
                if (packet != nullptr && wsNewIPCallback_) {
                    wsNewIPCallback_(std::move(packet));
                }
                buffer.consume(buffer.size()); // flush
            }
        } catch (const fptn::common::protobuf::protocol::ProcessingError &err) {
            spdlog::error("Session::run Processing error: {}", err.what());
        } catch (const fptn::common::protobuf::protocol::MessageError &err) {
            spdlog::error("Session::run Message error: {}", err.what());
        } catch (const fptn::common::protobuf::protocol::UnsoportedProtocolVersion &err) {
            spdlog::error("Session::run Unsupported protocol version: {}", err.what());
        } catch (boost::system::system_error& err) {
            spdlog::error("Session::run error: {}", err.what());
        } catch (const std::exception& e) {
            spdlog::error("Exception in run: {}", e.what());
        } catch(...) {
            spdlog::error("Session::run Unexpected error");
            break;
        }
    }
    close();
}


boost::asio::awaitable<bool> Session::processRequest() noexcept
{
    bool status = false;

    try {
        boost::system::error_code ec;
        boost::beast::flat_buffer buffer;
        boost::beast::http::request<boost::beast::http::string_body> request;

        co_await boost::beast::http::async_read(
            ws_.next_layer(),
            buffer,
            request,
            boost::asio::redirect_error(boost::asio::use_awaitable, ec)
        );

        // FIXME check ec

        if (boost::beast::websocket::is_upgrade(request)) {
            status = co_await handleWebSocket(std::move(request));
            if (status) {
                co_await ws_.async_accept(
                    request,
                    boost::asio::redirect_error(boost::asio::use_awaitable, ec)
                );
            }
        } else {
            status = co_await handleHttp(std::move(request));
        }
    } catch (boost::system::system_error& err) {
        spdlog::error("Session::handshake error: {}", err.what());
    }
    co_return status;
}

boost::asio::awaitable<bool> Session::handleHttp(const boost::beast::http::request<boost::beast::http::string_body>& request) noexcept
{
    const std::string url = request.target();
    const std::string method = request.method_string();

    if (method.empty() && url.empty()) {
        co_return false;
    }

    spdlog::info("HTTP {} {}", method, url);

    // default content types
    boost::beast::http::response<boost::beast::http::string_body> resp;
    resp.set(boost::beast::http::field::pragma, "no-cache");
    resp.set(boost::beast::http::field::server, "nginx/1.24.0");
    resp.set(boost::beast::http::field::connection, "keep-alive");
    resp.set(boost::beast::http::field::content_type, "text/html; charset=utf-8");
    resp.set(boost::beast::http::field::cache_control, "no-cache, no-store, must-revalidate");
    resp.set(boost::beast::http::field::expires, "Fri, 07 Jun 1974 04:00:00 GMT");
    resp.set("x_bitrix_composite", "Cache (200)");

    const ApiHandle handler = getApiHandle(apiHandles_, url, method);
    if (handler) {
        int status = handler(request, resp);
        resp.result(status);
    } else {
        // Return 404 if no handler found
        resp.result(boost::beast::http::status::not_found);
        resp.body() = "404 Not Found";
    }
    resp.prepare_payload();

    auto res_ptr = std::make_shared<boost::beast::http::response<boost::beast::http::string_body>>(std::move(resp));
    try {
        co_await boost::beast::http::async_write(ws_.next_layer(), *res_ptr, boost::asio::use_awaitable);
    } catch (const boost::beast::system_error& e) {
       //  spdlog::error("Error writing HTTP response: {}", e.what());
    }
    co_return false;
}

boost::asio::awaitable<bool> Session::handleWebSocket(const boost::beast::http::request<boost::beast::http::string_body>& request) noexcept
{
    if (request.find("Authorization") != request.end() && request.find("ClientIP") != request.end()) {
        clientId_ = CLIENT_ID++; // Increment the clientId after using it

        std::string token = request["Authorization"];
        boost::replace_first(token, "Bearer ", ""); // clean token string

        const std::string clientVpnIPv4Str = request["ClientIP"];
        const std::string clientIPStr = ws_.next_layer().next_layer().socket().remote_endpoint().address().to_string();

        // Create IPv4Address objects
        const pcpp::IPv4Address clientIP(clientIPStr);
        const pcpp::IPv4Address clientVpnIPv4(clientVpnIPv4Str);

        const std::string clientVpnIPv6Str = (
            request.find("ClientIPv6") != request.end()
            ? request["ClientIPv6"]
            : FPTN_CLIENT_DEFAULT_ADDRESS_IP6 // default value
        );
        const pcpp::IPv6Address clientVpnIPv6(clientVpnIPv6Str);
        // run
        const bool status = wsOpenCallback_(
            clientId_,
            clientIP,
            clientVpnIPv4,
            clientVpnIPv6,
            shared_from_this(),
            request.target(),
            token
        );
        co_return status;
    }
    co_return false;
}

void Session::close() noexcept
{
    if (!isRunning_) {
        return;
    }

    isRunning_ = false;
    try {
        boost::system::error_code ec;
        if (ws_.is_open()) {
            spdlog::info("--- close wss ---");
            ws_.close(boost::beast::websocket::close_code::normal, ec);
        }
        auto &ssl = ws_.next_layer();
        if (ssl.native_handle()) {
            spdlog::info("--- shutdown ssl ---");
            SSL_shutdown(ssl.native_handle());
        }

        auto &tcp = ssl.next_layer();
        if (tcp.socket().is_open()) {
            spdlog::info("--- close tcp socket ---");
            tcp.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            tcp.socket().close(ec);
        }
        if (clientId_ != MAX_CLIENT_ID && wsCloseCallback_) {
            spdlog::info("--- run callback ---");
            wsCloseCallback_(clientId_);
        }
        spdlog::info("--- close sucessfull ---");
    } catch (boost::system::system_error &err) {
        spdlog::error("Session::close error: {}", err.what());
    }
}

boost::asio::awaitable<void> Session::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    // FIXME REDUNDANT COPY
    boost::system::error_code ec;
    const std::string msg = fptn::common::protobuf::protocol::createPacket(std::move(packet));
    const boost::asio::const_buffer buffer(msg.data(), msg.size());

    if (isRunning_) {
        co_await ws_.async_write(
            buffer,
            boost::asio::redirect_error(boost::asio::use_awaitable, ec)
        );
        if (ec) {
            spdlog::error("Session::send error: {}", ec.what());
            close();
        }
    }
    co_return;
}
