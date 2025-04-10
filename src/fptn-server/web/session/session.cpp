#include <atomic>
#include <coroutine>
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


#include "session.h"


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
        strand_(ws_.get_executor()),
        write_channel_(ws_.get_executor(), 256),
        apiHandles_(apiHandles),
        wsOpenCallback_(wsOpenCallback),
        wsNewIPCallback_(wsNewIPCallback),
        wsCloseCallback_(wsCloseCallback),
        isInitComplete_(false),
        isQueueFull_(false)
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
        // Set a timeout to force reconnection every 2 hours
        boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::hours(2));
        isInitComplete_ = true;
    } catch (boost::system::system_error& err) {
        SPDLOG_ERROR("Session::init error: {}", err.what());
    } catch (const std::exception& e) {
        SPDLOG_ERROR("Session::init prepare: {}", e.what());
    }
}

Session::~Session()
{
    close();
}

boost::asio::awaitable<void> Session::run() noexcept
{
    boost::system::error_code ec;

    // check init status
    if (!isInitComplete_) {
        SPDLOG_ERROR("Session is not initialized. Closing session.");
        close();
        co_return;
    }

    co_await handleProxy("rutube.ru", 443);
    co_return;

    // do handshake
    co_await ws_.next_layer().async_handshake(
            boost::asio::ssl::stream_base::server,
            boost::asio::redirect_error(boost::asio::use_awaitable, ec)
    );
    if (ec) {
        SPDLOG_ERROR("Session handshake failed: {} ({})", ec.what(), ec.value());
        close();
        co_return;
    }
    isRunning_ = co_await processRequest();
    if (isRunning_) {
        auto self = shared_from_this();
        boost::asio::co_spawn(
            strand_,
            [self]() mutable -> boost::asio::awaitable<void> {
                return self->runReader();
            },
            boost::asio::detached
        );
        boost::asio::co_spawn(
            strand_,
            [self]() mutable -> boost::asio::awaitable<void> {
                return self->runSender();
            },
            boost::asio::detached
        );
    }
}

boost::asio::awaitable<void> Session::runReader() noexcept
{
    boost::system::error_code ec;
    boost::beast::flat_buffer buffer;
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
            SPDLOG_ERROR("Session::runReader Processing error: {}", err.what());
        } catch (const fptn::common::protobuf::protocol::MessageError &err) {
            SPDLOG_ERROR("Session::runReader Message error: {}", err.what());
        } catch (const fptn::common::protobuf::protocol::UnsoportedProtocolVersion &err) {
            SPDLOG_ERROR("Session::runReader Unsupported protocol version: {}", err.what());
        } catch (boost::system::system_error& err) {
            SPDLOG_ERROR("Session::runReader error: {}", err.what());
        } catch (const std::exception& e) {
            SPDLOG_ERROR("Exception in runReader: {}", e.what());
        } catch(...) {
            SPDLOG_ERROR("Session::runReader Unexpected error");
            break;
        }
    }
    close();
}

boost::asio::awaitable<void> Session::runSender() noexcept
{
    boost::system::error_code ec;

    auto token = boost::asio::redirect_error(boost::asio::use_awaitable, ec);

    std::string msg;
    msg.reserve(4096);

    while (isRunning_ && ws_.is_open()) {
        // read
        auto packet = co_await write_channel_.async_receive(token);
        if (!isRunning_ || !write_channel_.is_open() || ec) {
            SPDLOG_ERROR("Session::runSender close, ec = {}", ec.value());
            break;
        }
        if (packet != nullptr) {
            // send
            msg = fptn::common::protobuf::protocol::createPacket(std::move(packet));
            if (!msg.empty() ) {
                co_await ws_.async_write(boost::asio::buffer(msg.data(), msg.size()), token);
                if (ec) {
                    SPDLOG_ERROR("Session::runSender async_write error: {}", ec.what());
                    break;
                }
                msg.clear();
            }
        }
    }
    co_return;
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
        SPDLOG_ERROR("Session::handshake error: {}", err.what());
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

    SPDLOG_INFO("HTTP {} {}", method, url);

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
        //  SPDLOG_ERROR("Error writing HTTP response: {}", e.what());
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

boost::asio::awaitable<bool> Session::handleProxy(const std::string& sni, int port) noexcept
{
    auto& socket = ws_.next_layer().next_layer();
    boost::asio::ip::tcp::socket target_socket(co_await this_coro::executor);

    try {
        boost::asio::ip::tcp::resolver resolver(co_await this_coro::executor);
        const std::string port_str = std::to_string(port);
        auto endpoints = co_await resolver.async_resolve(sni, port_str, use_awaitable);
        co_await boost::asio::async_connect(target_socket, endpoints, use_awaitable);

//        auto ep = socket.remote_endpoint();
        auto ep = target_socket.local_endpoint();
        SPDLOG_INFO("Proxying {}:{} <-> {}:{}", ep.address().to_string(), ep.port(), sni, port_str);

        auto forward = [](auto& from, auto& to) -> boost::asio::awaitable<void> {
            try {
                std::array<char, 8192> buf{};
                boost::system::error_code ec;

                while (true) {
                    const auto n = co_await from.async_read_some(
                            boost::asio::buffer(buf),
                            boost::asio::redirect_error(use_awaitable, ec));

                    if (ec || n == 0) break;

                    co_await boost::asio::async_write(
                            to,
                            boost::asio::buffer(buf.data(), n),
                            boost::asio::redirect_error(use_awaitable, ec));

                    if (ec) break;
                }

                // Close only our end of the connection
//                boost::system::error_code ignore_ec;
                from.close();
            } catch (const boost::system::system_error& e) {
                SPDLOG_ERROR("Corutine1 system error: {} [{}]", e.what(), e.code().message());
            }
            co_return;
        };

        // Launch both forwarding directions in parallel
        auto [_, __, ___] = co_await boost::asio::experimental::make_parallel_group(
                boost::asio::co_spawn(
                        co_await this_coro::executor,
                        forward(socket, target_socket),
                        boost::asio::deferred
                ),
                boost::asio::co_spawn(
                        co_await this_coro::executor,
                        forward(target_socket, socket),
                        boost::asio::deferred
                )
        ).async_wait(
                boost::asio::experimental::wait_for_all(),
                use_awaitable
        );

        // Cleanup on error
//        boost::system::error_code ignore_ec;
//        if (socket.)
        socket.close();
        target_socket.close();

        co_return true;
    } catch (const boost::system::system_error& e) {
        SPDLOG_ERROR("Proxy system error: {} [{}]", e.what(), e.code().message());
    } catch (const std::exception& e) {
        SPDLOG_ERROR("Proxy error: {}", e.what());
    }

    co_return false;
}


//boost::asio::awaitable<bool> Session::handleProxy(const std::string& sni, int port) noexcept
//{
//    try {
//        auto& socket = ws_.next_layer().next_layer();
//
//        boost::asio::ip::tcp::resolver resolver(co_await this_coro::executor);
//        const std::string port_str = std::to_string(443); //std::to_string(port);
//        auto endpoints = co_await resolver.async_resolve(sni, port_str, use_awaitable);
//
//        boost::asio::ip::tcp::socket target_socket(co_await this_coro::executor);
//        co_await boost::asio::async_connect(target_socket, endpoints, use_awaitable);
//
////        auto ep = socket.remote_endpoint();
////        SPDLOG_INFO("Proxying {}:{} <-> {}:{}", ep.address().to_string(), ep.port(), sni, port_str);
//
//        auto forward = [](auto& from, auto& to) -> boost::asio::awaitable<void> {
//            std::array<char, 8192> buf{};
//            boost::system::error_code ec;
//            while (true) {
//                const std::size_t n = co_await from.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(use_awaitable, ec));
//                if (ec) {
//                    break;
//                }
//                co_await boost::asio::async_write(to, boost::asio::buffer(buf.data(), n), boost::asio::redirect_error(use_awaitable, ec));
//                if (ec) {
//                    break;
//                }
//            }
//            // Close both ends when done
////            boost::system::error_code ec;
//            from.close();
//            to.close();
//            co_return;
//        };
//
//        co_await boost::asio::experimental::wait_for_all(
//                boost::asio::co_spawn(
//                        co_await this_coro::executor,
//                        forward(socket, target_socket),
//                        boost::asio::use_awaitable
//                ),
//                boost::asio::co_spawn(
//                        co_await this_coro::executor,
//                        forward(target_socket, socket),
//                        boost::asio::use_awaitable
//                )
//        );
//
////        auto fwd1 = forward(socket, target_socket);
////        auto fwd2 = forward(target_socket, socket);
////
////        co_await std::when_all(fwd1, fwd2);
//
////        co_await (
////                boost::asio::co_spawn(
////                        co_await this_coro::executor,
////                        forward(socket, target_socket),
////                        boost::asio::use_awaitable
////                ) &&
////                boost::asio::co_spawn(
////                        co_await this_coro::executor,
////                        forward(target_socket, socket),
////                        boost::asio::use_awaitable
////                )
////        );
//        co_return true;
//    } catch (const boost::system::system_error& e) {
//        SPDLOG_ERROR("Proxy error: {}", e.what());
//        co_return false;
//    } catch (const std::exception& e) {
//        SPDLOG_ERROR("Unexpected error in proxy: {}", e.what());
//        co_return false;
//    }
//}


void Session::close() noexcept
{
    if (!isRunning_) {
        return;
    }

    const std::unique_lock<std::mutex> lock(mutex_);

    isRunning_ = false;
    write_channel_.close();
    try {
        boost::system::error_code ec;
        if (ws_.is_open()) {
            SPDLOG_INFO("--- close wss {} --- ", clientId_);
            ws_.close(boost::beast::websocket::close_code::normal, ec);
        }
        auto &ssl = ws_.next_layer();
        if (ssl.native_handle()) {
            SPDLOG_INFO("--- shutdown ssl {} ---", clientId_);
            SSL_shutdown(ssl.native_handle());
        }

        auto &tcp = ssl.next_layer();
        if (tcp.socket().is_open()) {
            SPDLOG_INFO("--- close tcp socket {} ---", clientId_);
            tcp.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            tcp.socket().close(ec);
        }
        if (clientId_ != MAX_CLIENT_ID && wsCloseCallback_) {
            SPDLOG_INFO("--- run callback {} ---", clientId_);
            wsCloseCallback_(clientId_);
        }
        SPDLOG_INFO("--- close sucessfull {} ---", clientId_);
    } catch (boost::system::system_error &err) {
        SPDLOG_ERROR("Session::close error: {}", err.what());
    }
}

boost::asio::awaitable<bool> Session::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    try {
        if (isRunning_ && write_channel_.is_open()) {
            const bool status = write_channel_.try_send(boost::system::error_code(), std::move(packet));
            if (status) {
                isQueueFull_ = false;
            } else if (!isQueueFull_) {
                // Log a warning only once when the queue first becomes full
                isQueueFull_ = true;
                spdlog::warn("Session::send the queue is full");
            }
        }
    } catch (boost::system::system_error& err) {
        SPDLOG_ERROR("Session::send error: {}", err.what());
        co_return false;
    }
    co_return true;
}
