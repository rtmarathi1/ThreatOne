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

class ISIEMEngine {
public:
    virtual ~ISIEMEngine() = default;

    virtual bool ingestLog(const LogEntry& entry) = 0;
    virtual std::vector<LogEntry> searchLogs(const std::string& query) = 0;
    virtual std::string createAlert(const SIEMAlert& alert) = 0;
    virtual std::vector<SIEMAlert> getAlerts() = 0;
    virtual std::string createRule(const SIEMRule& rule) = 0;
    virtual std::vector<SIEMRule> getRules() = 0;
};

} // namespace ThreatOne::SIEM
