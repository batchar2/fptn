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

void Metrics::UpdateStatistics(fptn::ClientID session_id,
    const std::string& username,
    std::size_t incoming_bytes,
    std::size_t outgoing_bytes) noexcept {
  const std::scoped_lock lock(mutex_);  // mutex

  auto& incoming_metric = incoming_bytes_counter_->Add(
      {{"username", username}, {"session_id", std::to_string(session_id)}});
  auto& outgoing_metric = outgoing_bytes_counter_->Add(
      {{"username", username}, {"session_id", std::to_string(session_id)}});
  incoming_metric.Increment(
      static_cast<double>(incoming_bytes) - incoming_metric.Value());
  outgoing_metric.Increment(
      static_cast<double>(outgoing_bytes) - outgoing_metric.Value());
}

void Metrics::UpdateActiveSessions(std::size_t count) noexcept {
  const std::scoped_lock lock(mutex_);  // mutex

  active_sessions_->Set(static_cast<double>(count));
}

std::string Metrics::Collect() noexcept {
  const std::scoped_lock lock(mutex_);  // mutex

  try {
    std::ostringstream result;
    prometheus::TextSerializer serializer;
    serializer.Serialize(result, registry_->Collect());
    return result.str();
  } catch (const std::exception& e) {
    return "Error collecting metrics: " + std::string(e.what());
  }
}
