#pragma once

#include <string>
#include <vector>
#include <unordered_map>

namespace ThreatOne::SIEM {

struct LogEntry {
    std::string id;
    std::string source;
    std::string message;
    std::string severity;
    std::string timestamp;
    std::unordered_map<std::string, std::string> metadata;
};

struct SIEMAlert {
    std::string id;
    std::string ruleId;
    std::string title;
    std::string severity;
    std::string description;
    std::vector<std::string> matchedLogIds;
    std::string timestamp;
};

struct SIEMRule {
    std::string id;
    std::string name;
    std::string condition;
    std::string severity;
    bool enabled = true;
};

enum class LogFormat {
    Syslog,
    WindowsEventLog,
    JSON,
    CEF,
    LEEF
};

struct ParsedField {
    std::string name;
    std::string value;
    std::string type;  // "string", "integer", "timestamp", etc.
};

struct CorrelationRule {
    std::string id;
    std::string name;
    std::string condition;  // Field condition to match (e.g., "event_type=login_failed")
    int timeWindowSeconds = 300;
    int threshold = 5;
    std::string severity;
    bool enabled = true;
};

struct SearchQuery {
    std::string text;
    std::unordered_map<std::string, std::string> fields;
    std::string timeStart;
    std::string timeEnd;
    int limit = 100;
};

struct DashboardMetrics {
    double eventsPerSecond = 0.0;
    std::vector<std::pair<std::string, int>> topSources;
    double alertRate = 0.0;
    long storageUsedBytes = 0;
    long totalLogs = 0;
};

class ISIEMEngine {
public:
    virtual ~ISIEMEngine() = default;

    virtual bool ingestLog(const LogEntry& entry) = 0;
    virtual std::vector<LogEntry> searchLogs(const std::string& query) = 0;
    virtual std::string createAlert(const SIEMAlert& alert) = 0;
    virtual std::vector<SIEMAlert> getAlerts() = 0;
    virtual std::string createRule(const SIEMRule& rule) = 0;
    virtual std::vector<SIEMRule> getRules() = 0;

    // Extended methods
    virtual bool ingestBatch(const std::vector<LogEntry>& entries) = 0;
    virtual std::vector<ParsedField> parseLog(const std::string& rawLog, LogFormat format) = 0;
    virtual std::string createCorrelationRule(const CorrelationRule& rule) = 0;
    virtual std::vector<SIEMAlert> evaluateRules() = 0;
    virtual std::vector<LogEntry> search(const SearchQuery& query) = 0;
    virtual DashboardMetrics getDashboardMetrics() = 0;
};

} // namespace ThreatOne::SIEM
