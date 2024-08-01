#include "server.h"

#include <functional>
#include <glog/logging.h>


using namespace fptn::web;


Server::Server(
    const fptn::nat::TableSPtr& natTable,
    std::uint16_t port,
    const bool use_https,
    const fptn::common::user::UserManagerSPtr& userManager,
    const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
    const int thread_number
)
    : 
        running_(false), 
        natTable_(natTable),
        http_(userManager, tokenManager),
        ws_(
            tokenManager,
            std::bind(&Server::newVpnConnection, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5), 
            std::bind(&Server::closeVpnConnection, this, std::placeholders::_1),
            std::bind(&Server::newIPPacketFromVPN, this, std::placeholders::_1)
        )
{
    if (use_https) {
        mainServer_.https_port = port;
        hssl_ctx_opt_t param;
        std::memset(&param, 0x00, sizeof(param));
        param.crt_file = tokenManager->serverCrt().c_str();
        param.key_file = tokenManager->serverKey().c_str();
        param.endpoint = HSSL_SERVER;
        if (mainServer_.newSslCtx(&param) != 0) {
            LOG(ERROR) << "new SSL_CTX failed!";
        }
    } else {
        mainServer_.port = port;
    }
    mainServer_.setThreadNum(thread_number);
    mainServer_.registerHttpService(http_.getService());
    mainServer_.registerWebSocketService(ws_.getService());
}

Server::~Server()
{
    stop();
}


bool Server::check() noexcept
{
    return true;
}

bool Server::start() noexcept
{
    running_ = true;
    serverThread_ = std::thread(&Server::runServerthread, this);
    senderThread_ = std::thread(&Server::runSenderThread, this);
    return serverThread_.joinable() && senderThread_.joinable();
}

bool Server::stop() noexcept
{
    running_ = false;
    if (serverThread_.joinable()) {
        mainServer_.stop();
        serverThread_.join();
    }
    if (senderThread_.joinable()) {
        senderThread_.join();
    }
    return true;
}

void Server::runServerthread() noexcept
{
    mainServer_.run();
}

void Server::runSenderThread() noexcept
{
    const std::chrono::milliseconds timeout{300};
    while (running_) {
        auto packet = toClient_.waitForPacket(timeout);
        if (packet != nullptr) {
            ws_.send(std::move(packet));
        }
    }
}

void Server::newVpnConnection(std::uint32_t clientId, const pcpp::IPv4Address& clientVpnIP, const pcpp::IPv4Address &clientIP, const std::string& username, int bandwidthBitesSeconds) noexcept
{
    LOG(INFO) << "NEW SESSION! Username=" << username << " ClientId=" << clientId << " Bandwidth=" << bandwidthBitesSeconds << " IP=" << clientIP.toString() << " VirtualIP=" << clientVpnIP.toString();
    auto shaper = std::make_shared<fptn::traffic_shaper::LeakyBucket>(bandwidthBitesSeconds);
    natTable_->createClientSession(clientId, clientVpnIP, shaper);
}

void Server::closeVpnConnection(std::uint32_t clientId) noexcept
{
    LOG(INFO) << "DEL SESSION! clientId=" << clientId;
    natTable_->delClientSession(clientId);
}

void Server::newIPPacketFromVPN(fptn::common::network::IPPacketPtr packet) noexcept
{
    fromClient_.push(std::move(packet));
}

void Server::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    toClient_.push(std::move(packet));
}

fptn::common::network::IPPacketPtr Server::waitForPacket(const std::chrono::milliseconds& duration) noexcept
{
    return fromClient_.waitForPacket(duration);
}
