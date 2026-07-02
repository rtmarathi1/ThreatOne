#pragma once
#include <unordered_map>
#include <optional>

#include "telemetry/ITelemetryManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <deque>
#include <cstdint>

namespace ThreatOne::Telemetry {

enum class TransportStatus {
    Ready,
    Sending,
    Failed,
    Disabled
};

struct TelemetryBatch {
    std::string id;
    std::vector<TelemetryEvent> events;
    std::vector<Metric> metrics;
    uint64_t totalSize = 0;
    std::string createdAt;
    std::string sentAt;
    bool compressed = false;
    TransportStatus status = TransportStatus::Ready;
};

struct TransportConfig {
    uint64_t maxBatchSize = 100;
    uint64_t maxBatchBytes = 1048576;  // 1MB
    uint64_t flushIntervalMs = 30000;  // 30 seconds
    bool compressionEnabled = true;
    int maxRetries = 3;
    std::string endpoint;
};

struct TransportStats {
    uint64_t totalBatchesSent = 0;
    uint64_t totalBatchesFailed = 0;
    uint64_t totalEventsSent = 0;
    uint64_t totalBytesSent = 0;
    uint64_t currentQueueSize = 0;
};

class TelemetryTransport {
public:
    TelemetryTransport();
    ~TelemetryTransport() = default;

    // Configuration
    void setConfig(const TransportConfig& config);
    [[nodiscard]] TransportConfig getConfig() const;

    // Batching
    bool enqueueEvent(const TelemetryEvent& event);
    bool enqueueMetric(const Metric& metric);
    std::string createBatch();
    bool flushBatch(const std::string& batchId);
    [[nodiscard]] std::optional<TelemetryBatch> getBatch(const std::string& batchId) const;

    // Queue management
    [[nodiscard]] uint64_t getQueuedEventCount() const;
    [[nodiscard]] uint64_t getQueuedMetricCount() const;
    [[nodiscard]] uint64_t getPendingBatchCount() const;
    void clearQueue();

    // Transport status
    [[nodiscard]] TransportStatus getStatus() const;
    void setEnabled(bool enabled);
    [[nodiscard]] bool isEnabled() const;

    // Statistics
    [[nodiscard]] TransportStats getStats() const;
    [[nodiscard]] uint64_t getTotalBatchesSent() const;

    // Retry handling
    bool retryBatch(const std::string& batchId);
    [[nodiscard]] std::vector<TelemetryBatch> getFailedBatches() const;

private:
    std::string generateBatchId();
    std::string getCurrentTimestamp() const;
    uint64_t estimateSize(const TelemetryEvent& event) const;

    mutable std::mutex mutex_;
    TransportConfig config_;
    std::deque<TelemetryEvent> eventQueue_;
    std::deque<Metric> metricQueue_;
    std::unordered_map<std::string, TelemetryBatch> batches_;
    TransportStatus status_ = TransportStatus::Ready;
    bool enabled_ = true;
    TransportStats stats_;
    int nextBatchId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Telemetry
