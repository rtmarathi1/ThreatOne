#pragma once

#include "siem/ISIEMEngine.h"
#include "siem/LogCollector.h"
#include "siem/LogParser.h"
#include "siem/EventNormalizer.h"
#include "siem/LogStorage.h"
#include "siem/SearchEngine.h"
#include "siem/DetectionRules.h"
#include "siem/SigmaRuleEngine.h"
#include "siem/CorrelationEngine.h"
#include "siem/AlertEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <memory>
#include <chrono>
#include <string>
#include <vector>

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

    // Access to sub-components for advanced usage
    [[nodiscard]] LogCollector& getLogCollector() { return *logCollector_; }
    [[nodiscard]] LogParser& getLogParser() { return *logParser_; }
    [[nodiscard]] EventNormalizer& getEventNormalizer() { return *eventNormalizer_; }
    [[nodiscard]] LogStorage& getLogStorage() { return *logStorage_; }
    [[nodiscard]] SearchEngine& getSearchEngine() { return *searchEngine_; }
    [[nodiscard]] DetectionRules& getDetectionRules() { return *detectionRules_; }
    [[nodiscard]] SigmaRuleEngine& getSigmaRuleEngine() { return *sigmaRuleEngine_; }
    [[nodiscard]] CorrelationEngine& getCorrelationEngine() { return *correlationEngine_; }
    [[nodiscard]] AlertEngine& getAlertEngine() { return *alertEngine_; }

private:
    // Sub-components
    std::shared_ptr<LogCollector> logCollector_;
    std::shared_ptr<LogParser> logParser_;
    std::shared_ptr<EventNormalizer> eventNormalizer_;
    std::shared_ptr<LogStorage> logStorage_;
    std::shared_ptr<SearchEngine> searchEngine_;
    std::shared_ptr<DetectionRules> detectionRules_;
    std::shared_ptr<SigmaRuleEngine> sigmaRuleEngine_;
    std::shared_ptr<CorrelationEngine> correlationEngine_;
    std::shared_ptr<AlertEngine> alertEngine_;

    // Metrics tracking
    std::chrono::steady_clock::time_point startTime_;

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
