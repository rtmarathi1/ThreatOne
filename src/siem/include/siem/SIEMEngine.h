#pragma once

#include "siem/ISIEMEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <atomic>
#include <map>
#include <chrono>

namespace ThreatOne::SIEM {

class SIEMEngine : public ISIEMEngine {
public:
    SIEMEngine();
    ~SIEMEngine() override = default;

    bool ingestLog(const LogEntry& entry) override;
    [[nodiscard]] std::vector<LogEntry> searchLogs(const std::string& query) override;
    std::string createAlert(const SIEMAlert& alert) override;
    [[nodiscard]] std::vector<SIEMAlert> getAlerts() override;
    std::string createRule(const SIEMRule& rule) override;
    [[nodiscard]] std::vector<SIEMRule> getRules() override;

    // Extended methods
    bool ingestBatch(const std::vector<LogEntry>& entries) override;
    [[nodiscard]] std::vector<ParsedField> parseLog(const std::string& rawLog, LogFormat format) override;
    std::string createCorrelationRule(const CorrelationRule& rule) override;
    [[nodiscard]] std::vector<SIEMAlert> evaluateRules() override;
    [[nodiscard]] std::vector<LogEntry> search(const SearchQuery& query) override;
    [[nodiscard]] DashboardMetrics getDashboardMetrics() override;

private:
    std::string generateLogId();
    std::string generateAlertId();
    std::string generateRuleId();
    std::string generateCorrelationRuleId();

    std::vector<ParsedField> parseSyslog(const std::string& rawLog) const;
    std::vector<ParsedField> parseJSON(const std::string& rawLog) const;
    std::vector<ParsedField> parseCEF(const std::string& rawLog) const;
    std::vector<ParsedField> parseLEEF(const std::string& rawLog) const;
    std::vector<ParsedField> parseWindowsEventLog(const std::string& rawLog) const;

    bool matchesCondition(const LogEntry& entry, const std::string& condition) const;
    bool isWithinTimeRange(const std::string& timestamp, const std::string& start, const std::string& end) const;

    mutable std::mutex mutex_;
    std::atomic<int> nextLogId_{1};
    std::atomic<int> nextAlertId_{1};
    std::atomic<int> nextRuleId_{1};
    std::atomic<int> nextCorrelationRuleId_{1};

    std::vector<LogEntry> logs_;
    std::map<std::string, SIEMAlert> alerts_;
    std::map<std::string, SIEMRule> rules_;
    std::map<std::string, CorrelationRule> correlationRules_;

    // Metrics tracking
    std::chrono::steady_clock::time_point startTime_;
    long totalIngested_ = 0;

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
