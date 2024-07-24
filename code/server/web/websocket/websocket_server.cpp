#include "websocket_server.h"

#include <glog/logging.h>

using namespace fptn::web;


WebsocketServer::WebsocketServer(
    const NewConnectionCallback &newConnection,
    const CloseConnectionCallback &closeConnection,
    const NewIPPacketCallback &newPacket
)
    :
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
            const auto clientIP = pcpp::IPv4Address(req->headers["ClientIP"]);

            {
                std::unique_lock<std::mutex> lock(mutex_);
                if (channels_.find(channelId) == channels_.end()) {
                    channels_.insert({channelId, channel});
                }
            }
            if (newConnectionCallback_)  {
                newConnectionCallback_(channelId, clientIP);
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
    auto packet = fptn::common::network::IPPacket::parse((const std::uint8_t*)msg.c_str(), msg.size(), channelId);
    if (packet != nullptr && newPacketCallback_) {
        newPacketCallback_(std::move(packet));
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
    std::unique_lock<std::mutex> lock(mutex_);
    auto it = channels_.find(packet->clientId());
    if (it != channels_.end()) {
        std::vector<std::uint8_t> serializedPacket = packet->serialize();
        it->second->send((const char*)serializedPacket.data(), serializedPacket.size());
    }
}