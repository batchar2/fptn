/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <mutex>
#include <string>

#include <prometheus/counter.h>   // NOLINT(build/include_order)
#include <prometheus/exposer.h>   // NOLINT(build/include_order)
#include <prometheus/gauge.h>     // NOLINT(build/include_order)
#include <prometheus/registry.h>  // NOLINT(build/include_order)

#include "common/client_id.h"

namespace fptn::statistic {
class Metrics {
 public:
  Metrics();
  void UpdateStatistics(fptn::ClientID session_id,
      const std::string& username,
      std::size_t incoming_bytes,
      std::size_t outgoing_bytes) noexcept;
  void UpdateActiveSessions(std::size_t count) noexcept;
  std::string Collect() noexcept;

 public:
  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;

 private:
  mutable std::mutex mutex_;

  std::unique_ptr<prometheus::Exposer> exposer_;
  std::shared_ptr<prometheus::Registry> registry_;

  prometheus::Gauge* active_sessions_;

  prometheus::Family<prometheus::Counter>* incoming_bytes_counter_;
  prometheus::Family<prometheus::Counter>* outgoing_bytes_counter_;
};

using MetricsSPtr = std::shared_ptr<Metrics>;

}  // namespace fptn::statistic
