#include "websocket_server.h"

#include <glog/logging.h>

#include <common/protobuf/protocol.h>


using namespace fptn::web;


WebsocketServer::WebsocketServer(
    const fptn::common::jwt_token::TokenManagerSPtr& tokenManager,
    const NewConnectionCallback &newConnection,
    const CloseConnectionCallback &closeConnection,
    const NewIPPacketCallback &newPacket
)
    :
        tokenManager_(tokenManager),
        newConnectionCallback_(newConnection),
        closeConnectionCallback_(closeConnection),
        newPacketCallback_(newPacket)
{
        ws_.onopen = std::bind(&WebsocketServer::onOpenHandle, this, std::placeholders::_1, std::placeholders::_2);
        ws_.onmessage = std::bind(&WebsocketServer::onMessageHandle, this, std::placeholders::_1, std::placeholders::_2);
        ws_.onclose = std::bind(&WebsocketServer::onCloseHandle, this, std::placeholders::_1);
}


void WebsocketServer::onOpenHandle(const WebSocketChannelPtr& channel, const HttpRequestPtr& req) noexcept
{
    if (websocket_uri_ == req->Path()) {
        if (req->headers.find("Authorization") != req->headers.end() && req->headers.find("ClientIP") != req->headers.end()) {
            const std::string token = req->headers["Authorization"];
            const std::uint32_t channelId = channel->id();
            const pcpp::IPv4Address clientVpnIP(req->headers["ClientIP"]);
            const pcpp::IPv4Address clientIP(req->client_addr.ip);

            std::string username;
            std::size_t bandwidthBitesSeconds = 0;
            if(tokenManager_->validate(token, username, bandwidthBitesSeconds)) {
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    if (channels_.find(channelId) == channels_.end()) {
                        channels_.insert({channelId, channel});
                    }
                }
                if (newConnectionCallback_)  {
                    newConnectionCallback_(channelId, clientVpnIP, clientIP, username, bandwidthBitesSeconds);
                }
            } else {
                LOG(WARNING) << "WRONG TOKEN: " << username << std::endl;
                channel->close();
            }
        
        } else {
            LOG(WARNING) << "CHECK: Authorization or ClientIP" << std::endl;
        }
    } else {
        LOG(WARNING) << "WRONG PATH: " << req->Path() << ", but the real path is: " << websocket_uri_ << std::endl;
        channel->close();
    }
}

void WebsocketServer::onMessageHandle(const WebSocketChannelPtr& channel, const std::string& msg) noexcept
{
    const std::uint32_t channelId = channel->id();
    try {
        const std::string rawIpPacket = fptn::common::protobuf::protocol::getPayload(msg);
        auto packet = fptn::common::network::IPPacket::parse(rawIpPacket, channelId);
        if (packet != nullptr && newPacketCallback_) {
            newPacketCallback_(std::move(packet));
        }
    } catch (const fptn::common::protobuf::protocol::ProcessingError &err) {
        LOG(ERROR) << "Processing error: " << err.what();
        const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_DEFAULT);
        channel->send(msg);
    } catch (const fptn::common::protobuf::protocol::MessageError &err) {
        LOG(ERROR) << "Message error: " << err.what();
    } catch (const fptn::common::protobuf::protocol::UnsoportedProtocolVersion &err) {
        LOG(ERROR) << "Unsupported protocol version: " << err.what();
        const std::string msg = fptn::common::protobuf::protocol::createError(err.what(), fptn::protocol::ERROR_WRONG_VERSION);
        channel->send(msg);
    } catch(...) {
        LOG(ERROR) << "Unexpected error: ";
    }
}

void WebsocketServer::onCloseHandle(const WebSocketChannelPtr& channel) noexcept
{
    const std::uint32_t channelId = channel->id();
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = channels_.find(channelId);
        if (it != channels_.end()) {
            channels_.erase(it);
        }
    }
    if (closeConnectionCallback_) {
        closeConnectionCallback_(channelId);
    }
}

void WebsocketServer::send(fptn::common::network::IPPacketPtr packet)
{
    try {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = channels_.find(packet->clientId());
        if (it != channels_.end()) {
            lock.unlock();
            try {
                const std::string msg = fptn::common::protobuf::protocol::createPacket(
                    std::move(packet)
                );
                it->second->send(msg);
            } catch (const std::runtime_error &err) {
                LOG(ERROR) << "Websockwt.send" << err.what();
            }
        }
    } catch(...) {
        LOG(ERROR) << "Websockwt.send: undefined error";
    } 
}
