#include "websocket_server.h"

#include <spdlog/spdlog.h>
#include <boost/algorithm/string/replace.hpp>

#include <common/protobuf/protocol.h>


using namespace fptn::web;


WebsocketServer::WebsocketServer(
        const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
        const NewConnectionCallback &newConnection,
        const CloseConnectionCallback &closeConnection,
        const NewIPPacketCallback &newPacket
)
    :
        running_(true),
        tokenManager_(tokenManager),
        newConnectionCallback_(newConnection),
        closeConnectionCallback_(closeConnection),
        newPacketCallback_(newPacket)
{
    ws_.onopen = std::bind(&WebsocketServer::onOpenHandle, this, std::placeholders::_1, std::placeholders::_2);
    ws_.onmessage = std::bind(&WebsocketServer::onMessageHandle, this, std::placeholders::_1, std::placeholders::_2);
    ws_.onclose = std::bind(&WebsocketServer::onCloseHandle, this, std::placeholders::_1);

    thread_ = std::thread(&WebsocketServer::run, this);
}

WebsocketServer::~WebsocketServer()
{
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
}

hv::WebSocketService* WebsocketServer::getService() noexcept
{
    return &ws_;
}

void WebsocketServer::onOpenHandle(const WebSocketChannelPtr& channel, const HttpRequestPtr& req) noexcept
{
    if (websocket_uri_ == req->Path()) {
        if (req->headers.find("Authorization") != req->headers.end() && req->headers.find("ClientIP") != req->headers.end()) {
            std::string token = req->headers["Authorization"];
            boost::replace_first(token, "Bearer ", ""); // clean token string

            const std::uint32_t channelId = channel->id();
            const pcpp::IPv4Address clientVpnIP(req->headers["ClientIP"]);
            const pcpp::IPv4Address clientIP(req->client_addr.ip);

            std::string username;
            std::size_t bandwidthBitesSeconds = 0;
            if(tokenManager_->validate(token, username, bandwidthBitesSeconds)) {
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    if (channels_.find(channelId) == channels_.end()) {
                        // save client
                        channels_.insert({channelId, channel});
                        // update alive information
                          channelsLastActive_.insert({channelId, std::chrono::steady_clock::now()});
                    }
                }
                if (newConnectionCallback_)  {
                    newConnectionCallback_(channelId, clientVpnIP, clientIP, username, bandwidthBitesSeconds);
                }
            } else {
                spdlog::warn("WRONG TOKEN: {}", username);
                channel->close();
            }
        } else {
            spdlog::warn("Required field missing: Authorization or ClientIP");
            channel->close();
        }
    } else {
        spdlog::warn("WRONG PATH: {}, but the real path is: {}",req->Path(), websocket_uri_);
        channel->close();
    }
}

void WebsocketServer::onMessageHandle(const WebSocketChannelPtr& channel, const std::string& msg) noexcept
{
    const std::uint32_t channelId = channel->id();
    try {
        std::string rawIpPacket = fptn::common::protobuf::protocol::getPayload(msg);
        auto packet = fptn::common::network::IPPacket::parse(std::move(rawIpPacket), channelId);
        if (packet != nullptr && newPacketCallback_) {
            newPacketCallback_(std::move(packet));
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (channels_.find(channelId) != channels_.end()) { // check
                    // update alive information
                    channelsLastActive_[channelId] = std::chrono::steady_clock::now();
                }
            }
        }
    } catch (const fptn::common::protobuf::protocol::ProcessingError &err) {
        spdlog::error("Processing error: {}", err.what());
        const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_DEFAULT);
        channel->send(msg);
    } catch (const fptn::common::protobuf::protocol::MessageError &err) {
        spdlog::error("Message error: {}", err.what());
    } catch (const fptn::common::protobuf::protocol::UnsoportedProtocolVersion &err) {
        spdlog::error("Unsupported protocol version: {}", err.what());
        const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_WRONG_VERSION);
        channel->send(msg);
    } catch(...) {
        spdlog::error("Unexpected error");
    }
}

void WebsocketServer::onCloseHandle(const WebSocketChannelPtr& channel) noexcept
{
    const std::uint32_t channelId = channel->id();
    {
        std::unique_lock<std::mutex> lock(mutex_);
        // clean channel
        auto channelIt = channels_.find(channelId);
        if (channelIt != channels_.end()) {
            channels_.erase(channelIt);
        }
        // clean last active channel
        auto activeChannelIt = channelsLastActive_.find(channelId);
        if (activeChannelIt != channelsLastActive_.end()) {
            channelsLastActive_.erase(activeChannelIt);
        }
    }
    if (closeConnectionCallback_) {
        closeConnectionCallback_(channelId);
    }
}

void WebsocketServer::send(fptn::common::network::IPPacketPtr packet) noexcept
{
    try {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = channels_.find(packet->clientId());
        if (it != channels_.end()) {
            const std::string msg = fptn::common::protobuf::protocol::createPacket(std::move(packet));
            it->second->send(msg, WS_OPCODE_BINARY);
        }
    } catch (const std::runtime_error &err) {
        spdlog::error("Websockwt.send: {}", err.what());
    } catch(...) {
        spdlog::error("Websockwt.send: undefined error");
    }
}

void WebsocketServer::run() noexcept
{
    constexpr std::chrono::seconds checkingInterval = std::chrono::seconds(3);
    std::chrono::steady_clock::time_point lastCheckTime = std::chrono::steady_clock::now();
    while (running_) {
        auto now = std::chrono::steady_clock::now();

        if (now - lastCheckTime >= checkingInterval) { // Check for inactive connections at regular intervals
            lastCheckTime = now;
            std::vector<std::uint32_t> channelsIds;

            std::unique_lock<std::mutex> lock(mutex_);

            // Identify channels that have been inactive beyond the timeout threshold
            for (auto &[channelId, lastActive]: channelsLastActive_) {
                const auto inactive = std::chrono::duration_cast<std::chrono::seconds>(now - lastActive).count();
                if (inactive > WEBSOCKET_IDLE_TIMEOUT_SECONDS) {
                    channelsIds.push_back(channelId);
                }
            }

            // Close the channel connection
            for (std::uint32_t channelId: channelsIds) {
                spdlog::info("Closing connection due to inactivity: ClientId={}", channelId);
                // Close the channel connection
                auto channelIt = channels_.find(channelId);
                if (channelIt != channels_.end()) {
                    channelIt->second->close(); // Close the channel
                    channels_.erase(channelIt); // Remove from active channels map
                }
                // Remove the channel's last active record
                auto activeChannelIt = channelsLastActive_.find(channelId);
                if (activeChannelIt != channelsLastActive_.end()) {
                    channelsLastActive_.erase(activeChannelIt);
                }
                // Invoke callback to notify that the connection has been closed
                if (closeConnectionCallback_) {
                    closeConnectionCallback_(channelId);
                }
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(350)); // sleep
        }
    }
}
