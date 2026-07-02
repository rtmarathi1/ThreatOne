#pragma once

#include "siem/ISIEMEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <map>
#include <atomic>

namespace ThreatOne::SIEM {

class DetectionRules {
public:
    DetectionRules();
    ~DetectionRules() = default;

    // Rule management
    std::string addRule(const SIEMRule& rule);
    bool removeRule(const std::string& ruleId);
    bool enableRule(const std::string& ruleId);
    bool disableRule(const std::string& ruleId);
    [[nodiscard]] std::vector<SIEMRule> getRules() const;
    [[nodiscard]] SIEMRule getRule(const std::string& ruleId) const;

    // Evaluate a log entry against all active rules
    // Returns IDs of rules that matched
    [[nodiscard]] std::vector<std::string> evaluate(const LogEntry& entry) const;

    // Check if an entry matches a specific condition
    [[nodiscard]] bool matchesCondition(const LogEntry& entry, const std::string& condition) const;

private:
    std::string generateRuleId();

    mutable std::mutex mutex_;
    std::map<std::string, SIEMRule> rules_;
    std::atomic<int> nextRuleId_{1};

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
