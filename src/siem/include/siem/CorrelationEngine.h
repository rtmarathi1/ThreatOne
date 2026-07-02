#pragma once

#include "siem/ISIEMEngine.h"
#include "siem/LogStorage.h"
#include "siem/DetectionRules.h"
#include "core/Logger.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <map>
#include <atomic>

namespace ThreatOne::SIEM {

class CorrelationEngine {
public:
    explicit CorrelationEngine(std::shared_ptr<LogStorage> storage);
    ~CorrelationEngine() = default;

    // Correlation rule management
    std::string addRule(const CorrelationRule& rule);
    bool removeRule(const std::string& ruleId);
    bool enableRule(const std::string& ruleId);
    bool disableRule(const std::string& ruleId);
    [[nodiscard]] std::vector<CorrelationRule> getRules() const;

    // Evaluate all correlation rules against stored logs
    // Returns alerts for rules that triggered
    [[nodiscard]] std::vector<SIEMAlert> evaluate();

    // Check if an entry matches a condition
    [[nodiscard]] bool matchesCondition(const LogEntry& entry, const std::string& condition) const;

private:
    std::string generateRuleId();
    std::string generateAlertId();

    mutable std::mutex mutex_;
    std::shared_ptr<LogStorage> storage_;
    std::map<std::string, CorrelationRule> rules_;
    std::atomic<int> nextRuleId_{1};
    std::atomic<int> nextAlertId_{1};

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
