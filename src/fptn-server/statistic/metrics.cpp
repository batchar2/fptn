/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "statistic/metrics.h"

#include <memory>
#include <sstream>
#include <string>

#include <prometheus/text_serializer.h>  // NOLINT(build/include_order)

using fptn::statistic::Metrics;

Metrics::Metrics() : registry_(std::make_shared<prometheus::Registry>()) {
  active_sessions_ = &prometheus::BuildGauge()
                          .Name("fptn_active_sessions")
                          .Help("Number of active VPN sessions")
                          .Register(*registry_)
                          .Add({});
  incoming_bytes_counter_ =
      &prometheus::BuildCounter()
           .Name("fptn_user_incoming_traffic_bytes")
           .Help("Incoming traffic for each user session in bytes")
           .Register(*registry_);
  outgoing_bytes_counter_ =
      &prometheus::BuildCounter()
           .Name("fptn_user_outgoing_traffic_bytes")
           .Help("Outgoing traffic for each user session in bytes")
           .Register(*registry_);
}

void Metrics::UpdateStatistics(fptn::ClientID sessionId,
    const std::string& username,
    std::size_t incomingBytes,
    std::size_t outgoingBytes) noexcept {
  const std::lock_guard<std::mutex> lock(mutex_);

  auto& incomingMetric = incoming_bytes_counter_->Add(
      {{"username", username}, {"session_id", std::to_string(sessionId)}});
  auto& outgoingMetric = outgoing_bytes_counter_->Add(
      {{"username", username}, {"session_id", std::to_string(sessionId)}});
  incomingMetric.Increment(
      static_cast<double>(incomingBytes) - incomingMetric.Value());
  outgoingMetric.Increment(
      static_cast<double>(outgoingBytes) - outgoingMetric.Value());
}

void Metrics::UpdateActiveSessions(std::size_t count) noexcept {
  const std::lock_guard<std::mutex> lock(mutex_);

  active_sessions_->Set(static_cast<double>(count));
}

std::string Metrics::Collect() noexcept {
  const std::lock_guard<std::mutex> lock(mutex_);

  try {
    std::ostringstream result;
    prometheus::TextSerializer serializer;
    serializer.Serialize(result, registry_->Collect());
    return result.str();
  } catch (const std::exception& e) {
    return "Error collecting metrics: " + std::string(e.what());
  }
}
