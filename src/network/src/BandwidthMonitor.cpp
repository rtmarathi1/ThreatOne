#include "network/BandwidthMonitor.h"

#include <algorithm>

namespace ThreatOne::Network {

BandwidthMonitor::BandwidthMonitor()
    : logger_(Core::Logger::instance().getModuleLogger("BandwidthMonitor")) {
    logger_.info("BandwidthMonitor initialized");
}

void BandwidthMonitor::recordTraffic(const std::string& connectionId, const std::string& appPath,
                                     uint64_t bytesSent, uint64_t bytesReceived) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& stats = connectionStats_[connectionId];
    stats.connectionId = connectionId;
    stats.appPath = appPath;
    stats.bytesSent += bytesSent;
    stats.bytesReceived += bytesReceived;

    // Update sliding window for rate limiting
    auto limitIt = rateLimits_.find(appPath);
    if (limitIt != rateLimits_.end()) {
        auto now = std::chrono::steady_clock::now();
        limitIt->second.windowEntries.push_back({now, bytesSent + bytesReceived});
    }

    logger_.trace("Recorded traffic for {}: sent={}, recv={}", connectionId, bytesSent, bytesReceived);
}

std::unordered_map<std::string, ConnectionStats> BandwidthMonitor::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return connectionStats_;
}

AppStats BandwidthMonitor::getAppStats(const std::string& appPath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    AppStats result;
    result.appPath = appPath;

    for (const auto& [id, stats] : connectionStats_) {
        if (stats.appPath == appPath) {
            result.totalBytesSent += stats.bytesSent;
            result.totalBytesReceived += stats.bytesReceived;
            result.connectionCount++;
        }
    }

    return result;
}

TrafficStats BandwidthMonitor::getTotalStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    TrafficStats total;

    for (const auto& [id, stats] : connectionStats_) {
        total.bytesSent += stats.bytesSent;
        total.bytesReceived += stats.bytesReceived;
    }

    return total;
}

void BandwidthMonitor::setRateLimit(const std::string& appPath, uint64_t bytesPerSecond) {
    std::lock_guard<std::mutex> lock(mutex_);
    rateLimits_[appPath].bytesPerSecond = bytesPerSecond;
    logger_.info("Set rate limit for {}: {} bytes/sec", appPath, bytesPerSecond);
}

bool BandwidthMonitor::checkRateLimit(const std::string& appPath, uint64_t bytes) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rateLimits_.find(appPath);
    if (it == rateLimits_.end()) {
        return true; // No limit set
    }

    if (it->second.bytesPerSecond == 0) {
        return false; // Zero limit means blocked
    }

    uint64_t windowBytes = getCurrentWindowBytes(it->second);
    return (windowBytes + bytes) <= it->second.bytesPerSecond;
}

void BandwidthMonitor::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    connectionStats_.clear();
    for (auto& [app, window] : rateLimits_) {
        window.windowEntries.clear();
    }
    logger_.info("BandwidthMonitor reset");
}

uint64_t BandwidthMonitor::getCurrentWindowBytes(const RateWindow& window) const {
    auto now = std::chrono::steady_clock::now();
    auto windowStart = now - std::chrono::seconds(1);

    uint64_t total = 0;
    // Clean up old entries and sum current window
    auto& entries = window.windowEntries;
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
            [&windowStart](const auto& entry) {
                return entry.first < windowStart;
            }),
        entries.end());

    for (const auto& entry : entries) {
        total += entry.second;
    }
    return total;
}

} // namespace ThreatOne::Network
