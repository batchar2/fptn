#include <iostream>
//#include <prometheus/collectable.h>
//
//#include <prometheus/registry.h>
//#include <prometheus/exposer.h>
#include <sstream>
#include "metrics.h"


#include <prometheus/text_serializer.h>

using namespace fptn::statistic;


Metrics::Metrics()
{
    registry_ = std::make_shared<prometheus::Registry>();
    activeSessions_ = &prometheus::BuildGauge()
            .Name("fptn_active_sessions")
            .Help("Number of active VPN sessions")
            .Register(*registry_)
            .Add({});
    userTrafficIncoming_ = &prometheus::BuildCounter()
            .Name("fptn_user_incoming_traffic_bytes")
            .Help("Incoming traffic for each user session in bytes")
            .Register(*registry_);
    userTrafficOutgoing_ = &prometheus::BuildCounter()
            .Name("fptn_user_outgoing_traffic_bytes")
            .Help("Outgoing traffic for each user session in bytes")
            .Register(*registry_);
}

void Metrics::updateStatistics(fptn::ClientID sessionId, const std::string& username, std::size_t incomingBytes, std::size_t outgoingBytes) noexcept
{
    const std::lock_guard<std::mutex> lock(mutex_);

    auto& incomingMetric = userTrafficIncoming_->Add({{"username", username}, {"session_id", std::to_string(sessionId)}});
    auto& outgoingMetric = userTrafficOutgoing_->Add({{"username", username}, {"session_id", std::to_string(sessionId)}});
    incomingMetric.Increment(static_cast<double>(incomingBytes) - incomingMetric.Value());
    outgoingMetric.Increment(static_cast<double>(outgoingBytes) - outgoingMetric.Value());
}

void Metrics::updateActiveSessions(std::size_t count) noexcept
{
    const std::lock_guard<std::mutex> lock(mutex_);

    activeSessions_->Set(static_cast<double>(count));
}


std::string Metrics::collect() noexcept
{
    const std::lock_guard<std::mutex> lock(mutex_);

    try {
        std::ostringstream result;
        prometheus::TextSerializer serializer;
        serializer.Serialize(result, registry_->Collect());
        return result.str();
    } catch (const std::exception &e) {
        return "Error collecting metrics: " + std::string(e.what());
    }
}