#include "siem/LogStorage.h"

#include <algorithm>

namespace ThreatOne::SIEM {

LogStorage::LogStorage()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("LogStorage")) {
    logger_.info("LogStorage initialized with default retention policy");
}

LogStorage::LogStorage(const RetentionPolicy& policy)
    : policy_(policy)
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("LogStorage")) {
    logger_.info("LogStorage initialized with maxEntries={}, maxAgeDays={}",
                 policy_.maxEntries, policy_.maxAgeDays);
}

std::string LogStorage::store(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    LogEntry stored = entry;
    if (stored.id.empty()) {
        stored.id = generateLogId();
    }

    // Apply retention if needed
    if (entries_.size() >= policy_.maxEntries && policy_.evictOldest) {
        if (!entries_.empty()) {
            entries_.pop_front();
        }
    }

    entries_.push_back(stored);
    totalIngested_++;

    logger_.debug("Stored log: id={}, source={}", stored.id, stored.source);
    return stored.id;
}

std::vector<std::string> LogStorage::storeBatch(const std::vector<LogEntry>& entries) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::string> ids;
    ids.reserve(entries.size());

    for (const auto& entry : entries) {
        LogEntry stored = entry;
        if (stored.id.empty()) {
            stored.id = generateLogId();
        }

        // Apply retention if needed
        if (entries_.size() >= policy_.maxEntries && policy_.evictOldest) {
            if (!entries_.empty()) {
                entries_.pop_front();
            }
        }

        entries_.push_back(stored);
        totalIngested_++;
        ids.push_back(stored.id);
    }

    logger_.info("Stored batch of {} logs", entries.size());
    return ids;
}

LogEntry LogStorage::getById(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Linear search since deque positions can shift after eviction
    for (const auto& entry : entries_) {
        if (entry.id == id) {
            return entry;
        }
    }
    return {};
}

std::vector<LogEntry> LogStorage::getAll() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {entries_.begin(), entries_.end()};
}

std::vector<LogEntry> LogStorage::getBySource(const std::string& source) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<LogEntry> results;
    for (const auto& entry : entries_) {
        if (entry.source == source) {
            results.push_back(entry);
        }
    }
    return results;
}

std::vector<LogEntry> LogStorage::getByTimeRange(const std::string& start,
                                                  const std::string& end) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<LogEntry> results;
    for (const auto& entry : entries_) {
        if (!start.empty() && entry.timestamp < start) continue;
        if (!end.empty() && entry.timestamp > end) continue;
        results.push_back(entry);
    }
    return results;
}

size_t LogStorage::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

long LogStorage::getStorageBytes() const {
    std::lock_guard<std::mutex> lock(mutex_);

    long bytes = 0;
    for (const auto& entry : entries_) {
        bytes += static_cast<long>(entry.message.size() + entry.source.size() + 100);
    }
    return bytes;
}

size_t LogStorage::applyRetention() {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t evicted = 0;
    while (entries_.size() > policy_.maxEntries) {
        entries_.pop_front();
        evicted++;
    }

    if (evicted > 0) {
        logger_.info("Retention applied: evicted {} entries", evicted);
    }
    return evicted;
}

void LogStorage::setRetentionPolicy(const RetentionPolicy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    policy_ = policy;
}

RetentionPolicy LogStorage::getRetentionPolicy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return policy_;
}

std::string LogStorage::generateLogId() {
    return "LOG-" + std::to_string(nextLogId_++);
}

std::unordered_map<std::string, int> LogStorage::getSourceCounts() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::unordered_map<std::string, int> counts;
    for (const auto& entry : entries_) {
        counts[entry.source]++;
    }
    return counts;
}

long LogStorage::getTotalIngested() const {
    return totalIngested_;
}

} // namespace ThreatOne::SIEM
