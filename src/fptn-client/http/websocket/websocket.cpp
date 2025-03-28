#include <spdlog/spdlog.h>
#include <boost/asio/strand.hpp>

#include "common/https/client.h"
#include "common/protobuf/protocol.h"

#include "websocket.h"


using namespace fptn::http;

Websocket::Websocket(
    const pcpp::IPv4Address& vpnServerIP,
    int vpnServerPort,
    const pcpp::IPv4Address& tunInterfaceAddressIPv4,
    const pcpp::IPv6Address& tunInterfaceAddressIPv6,
    const NewIPPacketCallback& newIPPktCallback,
    const std::string& sni,
    const std::string& token
) :
    ctx_{boost::asio::ssl::context::tlsv12_client},
    resolver_(boost::asio::make_strand(ioc_)),
    ws_(boost::asio::make_strand(ioc_), ctx_),
    strand_(ioc_.get_executor()),
    running_(false),
    vpnServerIP_(vpnServerIP),
    vpnServerPort_(vpnServerPort),
    tunInterfaceAddressIPv4_(tunInterfaceAddressIPv4),
    tunInterfaceAddressIPv6_(tunInterfaceAddressIPv6),
    newIPPktCallback_(newIPPktCallback),
    sni_(sni),
    token_(token)
{
    ctx_.set_options(boost::asio::ssl::context::no_sslv2 |
                    boost::asio::ssl::context::no_sslv3 |
                    boost::asio::ssl::context::no_tlsv1 |
                    boost::asio::ssl::context::no_tlsv1_1);
    // set chrome ciphers
    const std::string ciphers = fptn::common::https::chromeCiphers();
    SSL_CTX_set_cipher_list(ctx_.native_handle(), ciphers.c_str());
    // SSL
    ctx_.set_verify_mode(boost::asio::ssl::verify_none);
}

void Websocket::run() noexcept
{
    const std::string port_str = std::to_string(vpnServerPort_);
    auto self = shared_from_this();
    resolver_.async_resolve(
        vpnServerIP_.toString(),
        port_str,
        [self](boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results) {
            if (ec) {
                spdlog::error("Resolve error: {}", ec.message());
            } else {
                self->onResolve(ec, std::move(results));
            }
        }
    );
    running_ = true;

    if (ioc_.stopped()) {
        ioc_.restart();
    }
    ioc_.run();
}

bool Websocket::stop() noexcept
{
    const std::unique_lock<std::mutex> lock(mutex_);

    if (running_) {
        running_ = false;
        ioc_.stop();
        return true;
    }
    return false;
}

void Websocket::onResolve(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
{
    if (ec) {
        return fail(ec, "resolve");
    }
    // Set a timeout on the operation
    boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
    // Make the connection on the IP address we get from a lookup
    boost::beast::get_lowest_layer(ws_).async_connect(
        results,
        boost::beast::bind_front_handler(
            &Websocket::onConnect,
            shared_from_this()
        )
    );
}

void Websocket::onConnect(boost::beast::error_code ec,
                                   boost::asio::ip::tcp::resolver::results_type::endpoint_type)
{
    if (ec) {
        return fail(ec, "connect");
    }

    try {
        // Set a timeout on the operation
        boost::beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(ws_.next_layer().native_handle(), sni_.c_str())) {
            ec = boost::beast::error_code(static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category());
            return fail(ec, "connect");
        }
        ws_.text(false);
        ws_.binary(true); // Only binary
        ws_.auto_fragment(true); // FIXME NEED CHECK
        ws_.read_message_max(128 * 1024); // MaxSize (128 KB)
        ws_.set_option(
            boost::beast::websocket::stream_base::timeout::suggested(
                boost::beast::role_type::client
            )
        );
        boost::beast::get_lowest_layer(ws_).socket().set_option(
            boost::asio::ip::tcp::no_delay(true)
        ); // turn off the Nagle algorithm.

        ws_.next_layer().async_handshake(
            boost::asio::ssl::stream_base::client,
            boost::beast::bind_front_handler(
                &Websocket::onSslHandshake,
                shared_from_this()
            )
        );
    } catch (boost::system::system_error& err) {
        spdlog::error("onConnect error: {}", err.what());
        stop();
    }
}

void Websocket::onSslHandshake(boost::beast::error_code ec)
{
    std::cerr << "=== onSslHandshake" << std::endl;
    if (ec) {
        return fail(ec, "onSslHandshake");
    }
    // Turn off the timeout on the tcp_stream, because
    // the websocket stream has its own timeout system.
    boost::beast::get_lowest_layer(ws_).expires_never();

    // Set suggested timeout settings for the websocket
    ws_.set_option(
        boost::beast::websocket::stream_base::timeout::suggested(
            boost::beast::role_type::client
        )
    );

    // Set https headers
    ws_.set_option(
        boost::beast::websocket::stream_base::decorator(
            [this](boost::beast::websocket::request_type& req)
            {
                req.set("Authorization", "Bearer " + token_);
                req.set("ClientIP", tunInterfaceAddressIPv4_.toString());
                req.set("ClientIPv6", tunInterfaceAddressIPv6_.toString());
                req.set(
                    "UserAgent",
                    fmt::format("FptnClient({}/{})", FPTN_USER_OS, FPTN_VERSION)
                );
            }
        )
    );

    // Perform the websocket handshake
    ws_.async_handshake(
        vpnServerIP_.toString(), "/fptn",
        boost::beast::bind_front_handler(
            &Websocket::onHandshake,
            shared_from_this()
        )
    );
}

void Websocket::onHandshake(boost::beast::error_code ec)
{
    if (ec) {
        return fail(ec, "onHandshake");
    }
    doRead();
}

void Websocket::onRead(boost::beast::error_code ec, std::size_t transferred)
{
    if (ec) {
        return fail(ec, "read");
    }
    // FIXME REDUNDANT COPY
    const auto data = boost::beast::buffers_to_string(buffer_.data());
    std::string raw = fptn::common::protobuf::protocol::getPayload(data);
    auto packet = fptn::common::network::IPPacket::parse(std::move(raw));
    if (packet) {
        newIPPktCallback_(std::move(packet));
    }
    buffer_.consume(transferred);
    doRead();
}

void Websocket::onClose(boost::beast::error_code ec)
{
    if (ec) {
        return fail(ec, "close");
    }
}

void Websocket::fail(boost::beast::error_code ec, char const* what) noexcept
{
    spdlog::error("fail {}:", what, ec.what());
}

void Websocket::doRead()
{
    ws_.async_read(
        buffer_,
        boost::beast::bind_front_handler(
            &Websocket::onRead,
            shared_from_this()
        )
    );
}

bool Websocket::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    if (sendQueue_.size() < sendQueueMaxSize_) {
        boost::asio::post(
            strand_,
            [self = shared_from_this(), msg = std::move(packet)]() mutable {
                const std::unique_lock<std::mutex> lock(self->mutex_);

                const bool wasEmpty = self->sendQueue_.empty();
                self->sendQueue_.push(std::move(msg));
                if (wasEmpty) {
                    self->doWrite();
                }
            }
        );
        return true;
    }
    return false;
}

void Websocket::doWrite()
{
    try {
        if (!sendQueue_.empty()) {
            // PACK DATA
            fptn::common::network::IPPacketPtr packet = std::move(sendQueue_.front());
            const std::string msg = fptn::common::protobuf::protocol::createPacket(std::move(packet));
            const boost::asio::const_buffer buffer(msg.data(), msg.size());

            ws_.async_write(
                buffer,
                boost::beast::bind_front_handler(
                    &Websocket::onWrite,
                    shared_from_this()
                )
            );
        }
    } catch (boost::system::system_error& err) {
        spdlog::error("doWrite system_error: {}", err.what());
    } catch (const std::exception& e) {
        spdlog::error("doWrite error: {}", e.what());
    }
}

void Websocket::onWrite(boost::beast::error_code ec, std::size_t)
{
    if (ec) {
        fail(ec, "onWrite");
    }

    const std::unique_lock<std::mutex> lock(mutex_);

    sendQueue_.pop(); // remove writen item
    if (!sendQueue_.empty() && running_) {
        doWrite(); // send next message
    }
}
