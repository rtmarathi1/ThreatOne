#include "telemetry/TelemetryTransport.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Telemetry {

TelemetryTransport::TelemetryTransport()
    : logger_(Core::Logger::instance().getModuleLogger("TelemetryTransport")) {
    logger_.info("TelemetryTransport initialized");
}

std::string TelemetryTransport::generateBatchId() {
    return "BATCH-" + std::to_string(nextBatchId_++);
}

std::string TelemetryTransport::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

uint64_t TelemetryTransport::estimateSize(const TelemetryEvent& event) const {
    uint64_t size = event.name.size() + event.category.size() + event.timestamp.size();
    for (const auto& [k, v] : event.properties) {
        size += k.size() + v.size();
    }
    return size;
}

void TelemetryTransport::setConfig(const TransportConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    logger_.info("Transport config updated");
}

TransportConfig TelemetryTransport::getConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

bool TelemetryTransport::enqueueEvent(const TelemetryEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!enabled_) return false;

    eventQueue_.push_back(event);
    return true;
}

bool TelemetryTransport::enqueueMetric(const Metric& metric) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!enabled_) return false;

    metricQueue_.push_back(metric);
    return true;
}

std::string TelemetryTransport::createBatch() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (eventQueue_.empty() && metricQueue_.empty()) {
        return "";
    }

    TelemetryBatch batch;
    batch.id = generateBatchId();
    batch.createdAt = getCurrentTimestamp();
    batch.compressed = config_.compressionEnabled;
    batch.status = TransportStatus::Ready;

    uint64_t batchSize = 0;
    uint64_t itemCount = 0;

    while (!eventQueue_.empty() && itemCount < config_.maxBatchSize) {
        auto& event = eventQueue_.front();
        uint64_t eventSize = estimateSize(event);
        if (batchSize + eventSize > config_.maxBatchBytes && !batch.events.empty()) {
            break;
        }
        batch.events.push_back(event);
        batchSize += eventSize;
        ++itemCount;
        eventQueue_.pop_front();
    }

    while (!metricQueue_.empty() && itemCount < config_.maxBatchSize) {
        batch.metrics.push_back(metricQueue_.front());
        ++itemCount;
        metricQueue_.pop_front();
    }

    batch.totalSize = batchSize;
    batches_[batch.id] = batch;
    logger_.info("Created batch: {} ({} events, {} metrics)", batch.id,
                 batch.events.size(), batch.metrics.size());
    return batch.id;
}

bool TelemetryTransport::flushBatch(const std::string& batchId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = batches_.find(batchId);
    if (it == batches_.end()) return false;

    if (it->second.status != TransportStatus::Ready) return false;

    // Simulate sending
    it->second.status = TransportStatus::Sending;
    it->second.sentAt = getCurrentTimestamp();

    // Mark as sent successfully
    stats_.totalBatchesSent++;
    stats_.totalEventsSent += it->second.events.size();
    stats_.totalBytesSent += it->second.totalSize;

    // Remove batch after successful send
    batches_.erase(it);
    logger_.info("Flushed batch: {}", batchId);
    return true;
}

std::optional<TelemetryBatch> TelemetryTransport::getBatch(const std::string& batchId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = batches_.find(batchId);
    if (it == batches_.end()) return std::nullopt;
    return it->second;
}

uint64_t TelemetryTransport::getQueuedEventCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return eventQueue_.size();
}

uint64_t TelemetryTransport::getQueuedMetricCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return metricQueue_.size();
}

uint64_t TelemetryTransport::getPendingBatchCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return batches_.size();
}

void TelemetryTransport::clearQueue() {
    std::lock_guard<std::mutex> lock(mutex_);
    eventQueue_.clear();
    metricQueue_.clear();
}

TransportStatus TelemetryTransport::getStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!enabled_) return TransportStatus::Disabled;
    return status_;
}

void TelemetryTransport::setEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = enabled;
    if (!enabled) {
        status_ = TransportStatus::Disabled;
    } else {
        status_ = TransportStatus::Ready;
    }
}

bool TelemetryTransport::isEnabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return enabled_;
}

TransportStats TelemetryTransport::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    TransportStats s = stats_;
    s.currentQueueSize = eventQueue_.size() + metricQueue_.size();
    return s;
}

uint64_t TelemetryTransport::getTotalBatchesSent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.totalBatchesSent;
}

bool TelemetryTransport::retryBatch(const std::string& batchId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = batches_.find(batchId);
    if (it == batches_.end()) return false;

    if (it->second.status != TransportStatus::Failed) return false;

    it->second.status = TransportStatus::Ready;
    return true;
}

std::vector<TelemetryBatch> TelemetryTransport::getFailedBatches() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<TelemetryBatch> failed;
    for (const auto& [id, batch] : batches_) {
        if (batch.status == TransportStatus::Failed) {
            failed.push_back(batch);
        }
    }
    return failed;
}

} // namespace ThreatOne::Telemetry
