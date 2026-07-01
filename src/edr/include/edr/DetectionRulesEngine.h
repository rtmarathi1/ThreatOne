#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <regex>

#include "edr/BehaviorAnalyzer.h"
#include "core/Logger.h"

namespace ThreatOne::EDR {

// Condition for matching events
struct RuleCondition {
    std::string field;      // Field name in the event to check
    std::string op;         // Operator: "equals", "contains", "regex", "greater_than", "less_than", "in_list"
    std::string value;      // Value to compare against (for in_list, comma-separated)
};

// Detection rule definition
struct DetectionRule {
    std::string id;
    std::string name;
    std::string description;
    std::string severity;   // "info", "low", "medium", "high", "critical"
    std::string logic;      // "AND" or "OR" for combining conditions
    std::vector<RuleCondition> conditions;
    std::vector<std::string> actions; // "alert", "block", "quarantine", "log"
};

// Result of a rule matching an event
struct RuleMatch {
    std::string ruleId;
    std::string ruleName;
    std::string severity;
    std::vector<std::string> actions;
    std::string matchedField;
    std::string matchedValue;
};

class DetectionRulesEngine {
public:
    DetectionRulesEngine();
    ~DetectionRulesEngine() = default;

    // Load rules from JSON string
    bool loadRules(const std::string& jsonString);

    // Add a single rule programmatically
    void addRule(const DetectionRule& rule);

    // Evaluate an event against all rules
    [[nodiscard]] std::vector<RuleMatch> evaluate(const EDREvent& event) const;

    // Rule management
    [[nodiscard]] size_t getRuleCount() const;
    [[nodiscard]] std::vector<DetectionRule> getRules() const;
    void removeRule(const std::string& ruleId);
    void clearRules();

private:
    [[nodiscard]] bool evaluateCondition(const RuleCondition& condition, const EDREvent& event) const;
    [[nodiscard]] std::string getEventField(const EDREvent& event, const std::string& field) const;
    void compileRegexPatterns(const DetectionRule& rule);

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;
    std::vector<DetectionRule> rules_;

    // Pre-compiled regex patterns: key is the pattern string, value is the compiled regex
    std::unordered_map<std::string, std::regex> compiledRegexCache_;
};

} // namespace ThreatOne::EDR
