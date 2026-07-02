#include "siem/LogCollector.h"

#include <algorithm>

namespace ThreatOne::SIEM {

LogCollector::LogCollector()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("LogCollector")) {
    logger_.info("LogCollector initialized");
}

std::string LogCollector::generateSourceId() {
    return "SRC-" + std::to_string(nextSourceId_++);
}

std::string LogCollector::addSource(const LogSource& source) {
    std::lock_guard<std::mutex> lock(mutex_);

    LogSource stored = source;
    if (stored.id.empty()) {
        stored.id = generateSourceId();
    }
    sources_.push_back(stored);
    logger_.info("Added log source: id={}, name={}, type={}", stored.id, stored.name, stored.type);
    return stored.id;
}

bool LogCollector::removeSource(const std::string& sourceId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::remove_if(sources_.begin(), sources_.end(),
        [&sourceId](const LogSource& s) { return s.id == sourceId; });

    if (it != sources_.end()) {
        sources_.erase(it, sources_.end());
        logger_.info("Removed log source: id={}", sourceId);
        return true;
    }
    return false;
}

std::vector<LogSource> LogCollector::getSources() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sources_;
}

void LogCollector::startCollection() {
    collecting_ = true;
    logger_.info("Log collection started");
}

void LogCollector::stopCollection() {
    collecting_ = false;
    logger_.info("Log collection stopped");
}

bool LogCollector::isCollecting() const {
    return collecting_;
}

std::vector<LogEntry> LogCollector::getBuffer() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return buffer_;
}

void LogCollector::clearBuffer() {
    std::lock_guard<std::mutex> lock(mutex_);
    buffer_.clear();
}

size_t LogCollector::getBufferSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return buffer_.size();
}

bool LogCollector::collect(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    buffer_.push_back(entry);
    totalCollected_++;

    // Notify callbacks
    for (const auto& callback : callbacks_) {
        callback(entry);
    }

    logger_.debug("Collected log from source: {}", entry.source);
    return true;
}

bool LogCollector::collectBatch(const std::vector<LogEntry>& entries) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : entries) {
        buffer_.push_back(entry);
        totalCollected_++;

        for (const auto& callback : callbacks_) {
            callback(entry);
        }
    }

    logger_.info("Collected batch of {} logs", entries.size());
    return true;
}

void LogCollector::onLogCollected(LogCollectedCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.push_back(std::move(callback));
}

long LogCollector::getTotalCollected() const {
    return totalCollected_;
}

} // namespace ThreatOne::SIEM
