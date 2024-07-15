#include "server.h"


using namespace fptn::web;


server::server(
        std::uint16_t port,
        const bool use_https,
        const std::string& cert_file,
        const std::string& key_file,
        const websocket::new_connection_callback& new_connection,
        const websocket::close_connection_callback& close_connection,
        const int thread_number
)
    : ws_(new_connection, close_connection, nullptr)
{
    if (use_https) {
        main_server_.https_port = port;
        hssl_ctx_opt_t param;
        std::memset(&param, 0x00, sizeof(param));
        param.crt_file = cert_file.c_str();
        param.key_file = key_file.c_str();
        param.endpoint = HSSL_SERVER;
        if (main_server_.newSslCtx(&param) != 0) {
            LOG(ERROR) << "new SSL_CTX failed!";
        }
    } else {
        main_server_.port = port;
    }
    main_server_.setThreadNum(thread_number);
    main_server_.registerHttpService(http_.get_service());
    main_server_.registerWebSocketService(ws_.get_service());
}

server::~server()
{
    stop();
}

bool server::start(const websocket::recv_packet_callback &recv_packet) noexcept
{
    std::lock_guard<std::mutex> lock(mtx_);
    ws_.set_recv_packet_callback(recv_packet);
    th_ = std::thread(&server::run, this);
    return th_.joinable();
}

bool server::stop() noexcept
{
    std::lock_guard<std::mutex> lock(mtx_);
    if (th_.joinable()) {
        main_server_.stop();
        th_.join();
        return true;
    }
    return false;
}

void server::run() noexcept
{
    main_server_.run();
}
