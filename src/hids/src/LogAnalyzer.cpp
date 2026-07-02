#include "hids/LogAnalyzer.h"

#include <algorithm>
#include <chrono>
#include <regex>
#include <sstream>

namespace ThreatOne::HIDS {

LogAnalyzer::LogAnalyzer()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("LogAnalyzer")) {
    logger_.info("LogAnalyzer initialized");
}

std::string LogAnalyzer::generatePatternId() {
    return "LA-PAT-" + std::to_string(nextPatternId_++);
}

std::string LogAnalyzer::generateAnomalyId() {
    return "LA-ANO-" + std::to_string(nextAnomalyId_++);
}

std::string LogAnalyzer::generateLogEntryId() {
    return "LA-LOG-" + std::to_string(nextLogEntryId_++);
}

std::string LogAnalyzer::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

bool LogAnalyzer::matchesPattern(const std::string& text, const std::string& pattern) const {
    try {
        std::regex re(pattern);
        return std::regex_search(text, re);
    } catch (const std::regex_error&) {
        return false;
    }
}

std::string LogAnalyzer::addPattern(const LogPattern& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (pattern.pattern.empty()) {
        logger_.error("Cannot add pattern: empty regex");
        return "";
    }

    // Validate regex
    try {
        std::regex re(pattern.pattern);
        (void)re;
    } catch (const std::regex_error&) {
        logger_.error("Cannot add pattern: invalid regex");
        return "";
    }

    std::string id = generatePatternId();
    LogPattern newPattern = pattern;
    newPattern.id = id;
    patterns_[id] = newPattern;

    logger_.info("Added log pattern: {} ({})", pattern.name, id);
    return id;
}

bool LogAnalyzer::removePattern(const std::string& patternId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = patterns_.find(patternId);
    if (it == patterns_.end()) {
        return false;
    }
    patterns_.erase(it);
    return true;
}

bool LogAnalyzer::enablePattern(const std::string& patternId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = patterns_.find(patternId);
    if (it == patterns_.end()) {
        return false;
    }
    it->second.enabled = true;
    return true;
}

bool LogAnalyzer::disablePattern(const std::string& patternId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = patterns_.find(patternId);
    if (it == patterns_.end()) {
        return false;
    }
    it->second.enabled = false;
    return true;
}

std::vector<LogPattern> LogAnalyzer::getPatterns() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<LogPattern> result;
    result.reserve(patterns_.size());
    for (const auto& [id, pattern] : patterns_) {
        result.push_back(pattern);
    }
    return result;
}

uint64_t LogAnalyzer::getActivePatternCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t count = 0;
    for (const auto& [id, pattern] : patterns_) {
        if (pattern.enabled) {
            ++count;
        }
    }
    return count;
}

void LogAnalyzer::ingestEntry(const SystemLogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    SystemLogEntry newEntry = entry;
    if (newEntry.id.empty()) {
        newEntry.id = generateLogEntryId();
    }
    if (newEntry.timestamp.empty()) {
        newEntry.timestamp = getCurrentTimestamp();
    }

    // Track source frequency for anomaly detection
    sourceFrequency_[newEntry.source]++;

    // Match against patterns
    for (const auto& [patId, pattern] : patterns_) {
        if (!pattern.enabled) continue;

        if (matchesPattern(newEntry.message, pattern.pattern)) {
            newEntry.matched = true;
            newEntry.matchedPatternId = patId;
            matchedEntries_.push_back(newEntry);
            totalMatches_++;
            break;
        }
    }

    // Store entry
    logEntries_.push_back(newEntry);
    if (logEntries_.size() > kMaxEntries) {
        logEntries_.pop_front();
    }

    totalEntriesProcessed_++;
}

std::vector<SystemLogEntry> LogAnalyzer::getMatchedEntries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return matchedEntries_;
}

std::vector<SystemLogEntry> LogAnalyzer::getRecentEntries(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SystemLogEntry> result;
    size_t start = logEntries_.size() > count ? logEntries_.size() - count : 0;
    for (size_t i = start; i < logEntries_.size(); ++i) {
        result.push_back(logEntries_[i]);
    }
    return result;
}

std::vector<LogAnomalyResult> LogAnalyzer::detectAnomalies() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<LogAnomalyResult> anomalies;

    if (sourceFrequency_.empty()) {
        return anomalies;
    }

    // Calculate average frequency
    double totalFreq = 0.0;
    for (const auto& [source, freq] : sourceFrequency_) {
        totalFreq += static_cast<double>(freq);
    }
    double avgFreq = totalFreq / static_cast<double>(sourceFrequency_.size());

    // Detect frequency spikes
    for (const auto& [source, freq] : sourceFrequency_) {
        double ratio = static_cast<double>(freq) / (avgFreq > 0.0 ? avgFreq : 1.0);
        if (ratio > anomalyThreshold_) {
            LogAnomalyResult anomaly;
            anomaly.id = "LA-ANO-" + std::to_string(const_cast<int&>(nextAnomalyId_)++);
            anomaly.type = AnomalyType::FrequencySpike;
            anomaly.description = "Source '" + source + "' has " +
                                  std::to_string(freq) + " entries (ratio: " +
                                  std::to_string(ratio) + ")";
            anomaly.source = source;
            anomaly.score = ratio;
            anomaly.timestamp = "";
            anomalies.push_back(anomaly);
        }
    }

    return anomalies;
}

void LogAnalyzer::setAnomalyThreshold(double threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    anomalyThreshold_ = threshold;
}

double LogAnalyzer::getAnomalyThreshold() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return anomalyThreshold_;
}

LogAnalyzerStats LogAnalyzer::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    LogAnalyzerStats stats;
    stats.totalEntriesProcessed = totalEntriesProcessed_;
    stats.totalMatches = totalMatches_;
    stats.totalAnomalies = 0;
    stats.activePatterns = 0;
    for (const auto& [id, pattern] : patterns_) {
        if (pattern.enabled) {
            stats.activePatterns++;
        }
    }
    return stats;
}

void LogAnalyzer::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    totalEntriesProcessed_ = 0;
    totalMatches_ = 0;
    sourceFrequency_.clear();
}

} // namespace ThreatOne::HIDS
