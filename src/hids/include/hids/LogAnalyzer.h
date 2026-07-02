#pragma once

#include "hids/IHIDSEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <deque>
#include <cstdint>

namespace ThreatOne::HIDS {

enum class AnomalyType {
    FrequencySpike,
    UnusualSource,
    PatternDeviation,
    TimeAnomaly
};

struct LogAnomalyResult {
    std::string id;
    AnomalyType type = AnomalyType::FrequencySpike;
    std::string description;
    std::string source;
    double score = 0.0;
    std::string timestamp;
};

struct LogAnalyzerStats {
    uint64_t totalEntriesProcessed = 0;
    uint64_t totalMatches = 0;
    uint64_t totalAnomalies = 0;
    uint64_t activePatterns = 0;
};

class LogAnalyzer {
public:
    LogAnalyzer();
    ~LogAnalyzer() = default;

    // Pattern management
    std::string addPattern(const LogPattern& pattern);
    bool removePattern(const std::string& patternId);
    bool enablePattern(const std::string& patternId);
    bool disablePattern(const std::string& patternId);
    [[nodiscard]] std::vector<LogPattern> getPatterns() const;
    [[nodiscard]] uint64_t getActivePatternCount() const;

    // Log analysis
    void ingestEntry(const SystemLogEntry& entry);
    [[nodiscard]] std::vector<SystemLogEntry> getMatchedEntries() const;
    [[nodiscard]] std::vector<SystemLogEntry> getRecentEntries(size_t count) const;

    // Anomaly detection
    [[nodiscard]] std::vector<LogAnomalyResult> detectAnomalies() const;
    void setAnomalyThreshold(double threshold);
    [[nodiscard]] double getAnomalyThreshold() const;

    // Statistics
    [[nodiscard]] LogAnalyzerStats getStats() const;
    void resetStats();

private:
    std::string generatePatternId();
    std::string generateAnomalyId();
    std::string generateLogEntryId();
    std::string getCurrentTimestamp() const;
    bool matchesPattern(const std::string& text, const std::string& pattern) const;

    mutable std::mutex mutex_;

    // Patterns
    std::map<std::string, LogPattern> patterns_;

    // Entries
    std::deque<SystemLogEntry> logEntries_;
    std::vector<SystemLogEntry> matchedEntries_;

    // Anomaly detection
    double anomalyThreshold_ = 3.0;
    std::map<std::string, uint64_t> sourceFrequency_;

    // Stats
    uint64_t totalEntriesProcessed_ = 0;
    uint64_t totalMatches_ = 0;

    int nextPatternId_ = 1;
    int nextAnomalyId_ = 1;
    int nextLogEntryId_ = 1;

    static constexpr size_t kMaxEntries = 10000;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::HIDS
