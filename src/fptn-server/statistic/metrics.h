#pragma once

#include <mutex>
#include <string>

#include <prometheus/gauge.h>
#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>

#include <common/client_id.h>


namespace fptn::statistic
{
    class Metrics
    {
    public:
        Metrics();
        void updateStatistics(fptn::ClientID sessionId, const std::string& username, std::size_t incoming_bytes, std::size_t outgoing_bytes) noexcept;
        void updateActiveSessions(std::size_t count) noexcept;
        std::string collect() noexcept;
    public:
        Metrics(const Metrics&) = delete;
        Metrics& operator=(const Metrics&) = delete;
    private:
        std::mutex mutex_;

        std::unique_ptr<prometheus::Exposer> exposer_;
        std::shared_ptr<prometheus::Registry> registry_;

        prometheus::Gauge* activeSessions_;

        prometheus::Family<prometheus::Counter>* userTrafficIncoming_;
        prometheus::Family<prometheus::Counter>* userTrafficOutgoing_;
    };

    using MetricsSPtr = std::shared_ptr<Metrics>;

}
