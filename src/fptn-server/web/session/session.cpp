#include "session.h"

#include <atomic>
#include <spdlog/spdlog.h>
#include <boost/algorithm/string/replace.hpp>


using namespace fptn::web;


static std::atomic<fptn::ClientID> CLIENT_ID = 0;


Session::Session(boost::asio::ip::tcp::socket&& socket,
    boost::asio::ssl::context& ctx,
    const ApiHandleMap& apiHandles,
    WebSocketOpenConnectionCallback wsOpenCallback,
    WebSocketNewIPPacketCallback wsNewIPCallback,
    WebSocketCloseConnectionCallback wsCloseCallback,
    int timerTimeoutSeconds
)
    :
        isRunning_(false),
        ws_(std::move(socket), ctx),
        apiHandles_(apiHandles),
        wsOpenCallback_(wsOpenCallback),
        wsNewIPCallback_(wsNewIPCallback),
        wsCloseCallback_(wsCloseCallback),
        timer_(ws_.get_executor()),
        timerTimeoutSeconds_(timerTimeoutSeconds)
{
    ws_.text(false);
    ws_.binary(true); // Only binary
    ws_.auto_fragment(false); // Disable autofragment
    ws_.read_message_max(64 * 1024); // MaxSize (64 KB)
    ws_.set_option(
        boost::beast::websocket::stream_base::timeout::suggested(
            boost::beast::role_type::server
        )
    );
    ws_.set_option(
        boost::beast::websocket::stream_base::timeout{
            std::chrono::seconds(10), // Handshake timeout
            std::chrono::seconds(30), // Idle timeout
            true                      // Enable ping timeout
        }
    );
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::minutes(30));
}

bool Session::run() noexcept
{
    boost::asio::dispatch(
        ws_.get_executor(),
        boost::beast::bind_front_handler(
            &Session::onRun,
            shared_from_this()
        )
    );
    return true;
}

void Session::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    // FIXME REDUNDANT COPY
    const std::string msg = fptn::common::protobuf::protocol::createPacket(std::move(packet));
    const boost::asio::const_buffer buffer(msg.data(), msg.size());

    ws_.binary(true);
    ws_.async_write(
        buffer,
        boost::beast::bind_front_handler(
            &Session::onWrite,
            shared_from_this()
        )
    );
}

void Session::close() noexcept
{
    try {
        isRunning_ = false;
        boost::beast::get_lowest_layer(ws_).close();
    } catch (boost::system::system_error& err) {
        spdlog::error("Session::close error: {}", err.what());
    }
}

void Session::startTimer()
{
    boost::beast::error_code ec;
    timer_.expires_from_now(std::chrono::seconds(timerTimeoutSeconds_), ec);
    timer_.async_wait(boost::beast::bind_front_handler(&Session::onTimer, shared_from_this()));
}

void Session::cancelTimer()
{
    boost::beast::error_code ec;
    timer_.cancel(ec);
}

void Session::onTimer(boost::beast::error_code ec)
{
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }
    std::cerr << "TIMER" << std::endl;
    close();
    if (wsCloseCallback_) {
        wsCloseCallback_(clientId_);
    }
}

void Session::onRun()
{
    // SSL Handshake
    ws_.next_layer().async_handshake(
        boost::asio::ssl::stream_base::server,
        boost::beast::bind_front_handler(
            &Session::onHandshake,
            shared_from_this()
        )
    );
}

void Session::onHandshake(boost::beast::error_code ec)
{
    if (ec) {
        return;
    }
    auto self = shared_from_this();
    boost::beast::http::async_read(
        ws_.next_layer(),
        incomingBuffer_,
        request_,
        [self](boost::beast::error_code ec, std::size_t) mutable {
            if (ec) {
                spdlog::error("Error reading request: {}", ec.message());
                return;
            }
            self->checkRequest();
        }
    );
}

void Session::checkRequest()
{
    if (boost::beast::websocket::is_upgrade(request_)) {
        if (request_.find("Authorization") != request_.end() && request_.find("ClientIP") != request_.end()) {
            clientId_ = CLIENT_ID++; // Increment the clientId after using it

            std::string token = request_["Authorization"];
            boost::replace_first(token, "Bearer ", ""); // clean token string

            const std::string clientVpnIPv4Str = request_["ClientIP"];
            // Get the client's IP from the WebSocket connection
            const std::string clientIPStr = ws_.next_layer().next_layer().socket().remote_endpoint().address().to_string();

            // Create IPv4Address objects
            const pcpp::IPv4Address clientIP(clientIPStr);
            const pcpp::IPv4Address clientVpnIPv4(clientVpnIPv4Str);

            const std::string clientVpnIPv6Str = (
                request_.find("ClientIPv6") != request_.end()
                ? request_["ClientIPv6"]
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
                request_.target(),
                token
            );
            if (status) {
                isRunning_ = true;
                ws_.async_accept(
                    request_,
                    [this](boost::beast::error_code ec) {
                        onAccept(ec);
                    }
                );
            } else {
                // close connection
                close();
            }
        }
    } else {
        handleHttp();
    }
}

void Session::handleHttp()
{
    const std::string url = request_.target();
    const std::string method = request_.method_string();

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
        int status = handler(request_, resp);
        resp.result(status);
    } else {
        // Return 404 if no handler found
        resp.result(boost::beast::http::status::not_found);
        resp.body() = "404 Not Found";
    }
    resp.prepare_payload();

    auto self = shared_from_this();
    auto res_ptr = std::make_shared<boost::beast::http::response<boost::beast::http::string_body>>(std::move(resp));
    boost::beast::http::async_write(
        ws_.next_layer(), *res_ptr,
        [self, res_ptr](boost::beast::error_code ec, std::size_t) {
            if (ec) {
                spdlog::error("Error writing HTTP response: {}", ec.message());
            }
        }
    );
}

void Session::onAccept(boost::beast::error_code ec)
{
    const std::unique_lock<std::mutex> lock(mutex_);

    if (ec) {
        spdlog::error("Error accept: {}", ec.message());
        return;
    }
    doRead();
}

void Session::doRead()
{
    if (isRunning_) {
        startTimer();
        ws_.async_read(
            incomingBuffer_,
            boost::beast::bind_front_handler(
                &Session::onRead,
                shared_from_this()
            )
        );
    }
}

void Session::onRead(boost::beast::error_code ec, std::size_t)
{
    const std::unique_lock<std::mutex> lock(mutex_);

    cancelTimer();
    if (isRunning_) {
        if (ec) {
            if (ec == boost::beast::websocket::error::closed) {
                std::cerr << "CLOSE ON READ" << std::endl;
//                close();
//                if (wsCloseCallback_) {
//                    wsCloseCallback_(clientId_);
//                }
            }
            spdlog::error("Error reading WebSocket message: {}", ec.message());
            return;
        }

        // parse data
        try {
            const std::string rawdata = boost::beast::buffers_to_string(incomingBuffer_.data());
            incomingBuffer_.consume(incomingBuffer_.size());

            std::string rawip = fptn::common::protobuf::protocol::getPayload(rawdata);
            auto packet = fptn::common::network::IPPacket::parse(std::move(rawip), clientId_);
            if (packet != nullptr && wsNewIPCallback_) {
                wsNewIPCallback_(std::move(packet));
            }
        } catch (const fptn::common::protobuf::protocol::ProcessingError &err) {
            spdlog::error("Processing error: {}", err.what());
        } catch (const fptn::common::protobuf::protocol::MessageError &err) {
            spdlog::error("Message error: {}", err.what());
        } catch (const fptn::common::protobuf::protocol::UnsoportedProtocolVersion &err) {
            spdlog::error("Unsupported protocol version: {}", err.what());
        } catch(...) {
            spdlog::error("Unexpected error");
        }

        // read again
        doRead();
    }
}

void Session::onWrite(boost::beast::error_code ec, std::size_t)
{
    const std::unique_lock<std::mutex> lock(mutex_);

    if (isRunning_) {
        if (ec) {
            spdlog::error("Error write: {}", ec.message());
//            return;
        }
        doRead();
    }
}
