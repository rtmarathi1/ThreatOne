#pragma once

#include "siem/ISIEMEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <chrono>
#include <atomic>

namespace ThreatOne::SIEM {

// Retention policy configuration
struct RetentionPolicy {
    size_t maxEntries = 100000;
    int maxAgeDays = 90;
    bool evictOldest = true;
};

class LogStorage {
public:
    LogStorage();
    explicit LogStorage(const RetentionPolicy& policy);
    ~LogStorage() = default;

    // Store a log entry
    std::string store(const LogEntry& entry);

    // Store a batch of entries
    std::vector<std::string> storeBatch(const std::vector<LogEntry>& entries);

    // Retrieve by ID
    [[nodiscard]] LogEntry getById(const std::string& id) const;

    // Get all entries
    [[nodiscard]] std::vector<LogEntry> getAll() const;

    // Get entries by source
    [[nodiscard]] std::vector<LogEntry> getBySource(const std::string& source) const;

    // Get entries within time range
    [[nodiscard]] std::vector<LogEntry> getByTimeRange(const std::string& start,
                                                       const std::string& end) const;

    // Get total count
    [[nodiscard]] size_t count() const;

    // Get storage size estimate in bytes
    [[nodiscard]] long getStorageBytes() const;

    // Apply retention policy (evict old entries)
    size_t applyRetention();

    // Set retention policy
    void setRetentionPolicy(const RetentionPolicy& policy);
    [[nodiscard]] RetentionPolicy getRetentionPolicy() const;

    // Generate a unique log ID
    std::string generateLogId();

    // Source statistics
    [[nodiscard]] std::unordered_map<std::string, int> getSourceCounts() const;

    // Get total number of entries ever stored
    [[nodiscard]] long getTotalIngested() const;

private:
    mutable std::mutex mutex_;
    std::deque<LogEntry> entries_;
    std::unordered_map<std::string, size_t> idIndex_;  // id -> position in deque
    RetentionPolicy policy_;
    std::atomic<int> nextLogId_{1};
    std::atomic<long> totalIngested_{0};

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
