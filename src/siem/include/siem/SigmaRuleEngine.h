#pragma once

#include "siem/ISIEMEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <map>
#include <atomic>

namespace ThreatOne::SIEM {

// Sigma rule condition types
enum class SigmaConditionOp {
    And,
    Or,
    Not
};

// A single field match in a Sigma rule detection section
struct SigmaFieldMatch {
    std::string field;
    std::vector<std::string> values;  // any of these values matches
    bool caseSensitive = false;
    bool isRegex = false;
};

// A detection definition (named set of field matches)
struct SigmaDetection {
    std::string name;
    std::vector<SigmaFieldMatch> fieldMatches;
};

// A Sigma-style rule
struct SigmaRule {
    std::string id;
    std::string title;
    std::string description;
    std::string severity;  // "low", "medium", "high", "critical"
    std::string status;    // "experimental", "test", "stable"
    bool enabled = true;

    // Detection section
    std::vector<SigmaDetection> detections;
    std::string condition;  // Condition DSL: "selection1 AND selection2", "selection1 OR NOT filter1"

    // Metadata
    std::vector<std::string> tags;
    std::string author;
};

// Result of Sigma rule evaluation
struct SigmaMatch {
    std::string ruleId;
    std::string ruleTitle;
    std::string severity;
    std::vector<std::string> matchedFields;
};

class SigmaRuleEngine {
public:
    SigmaRuleEngine();
    ~SigmaRuleEngine() = default;

    // Rule management
    std::string addRule(const SigmaRule& rule);
    bool removeRule(const std::string& ruleId);
    [[nodiscard]] std::vector<SigmaRule> getRules() const;

    // Evaluate a log entry against all Sigma rules
    [[nodiscard]] std::vector<SigmaMatch> evaluate(const LogEntry& entry) const;

    // Evaluate against a single rule
    [[nodiscard]] bool evaluateRule(const LogEntry& entry, const SigmaRule& rule) const;

private:
    std::string generateRuleId();
    [[nodiscard]] bool evaluateDetection(const LogEntry& entry,
                                         const SigmaDetection& detection) const;
    [[nodiscard]] bool evaluateCondition(const LogEntry& entry,
                                         const SigmaRule& rule) const;
    [[nodiscard]] bool fieldMatchesValue(const std::string& fieldValue,
                                         const SigmaFieldMatch& match) const;
    [[nodiscard]] std::string getFieldValue(const LogEntry& entry,
                                            const std::string& field) const;

    mutable std::mutex mutex_;
    std::map<std::string, SigmaRule> rules_;
    std::atomic<int> nextRuleId_{1};

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SIEM
