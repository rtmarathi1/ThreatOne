#pragma once
#include <optional>

#include "sandbox/ISandboxEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace ThreatOne::Sandbox {

struct AnalysisRule {
    std::string id;
    std::string name;
    std::string description;
    int severityWeight = 1;  // 1-10
    std::string behaviorPattern;  // keyword to match
    bool enabled = true;
};

struct VerdictDetails {
    SandboxVerdict verdict = SandboxVerdict::Unknown;
    double confidenceScore = 0.0;  // 0.0 - 100.0
    double threatScore = 0.0;      // 0.0 - 100.0
    std::vector<std::string> matchedRules;
    std::vector<std::string> indicators;
    std::string rationale;
};

class SandboxAnalyzer {
public:
    SandboxAnalyzer();
    ~SandboxAnalyzer() = default;

    // Rule management
    std::string addAnalysisRule(const AnalysisRule& rule);
    bool removeAnalysisRule(const std::string& ruleId);
    bool enableRule(const std::string& ruleId, bool enabled);
    [[nodiscard]] std::vector<AnalysisRule> getAnalysisRules() const;
    [[nodiscard]] std::optional<AnalysisRule> getRule(const std::string& ruleId) const;

    // Analysis
    VerdictDetails analyzeBehaviors(const std::vector<std::string>& behaviors) const;
    SandboxVerdict computeVerdict(const std::vector<std::string>& behaviors) const;
    double computeThreatScore(const std::vector<std::string>& behaviors) const;

    // IOC extraction
    std::vector<IOCInfo> extractIOCs(const BehaviorReport& report) const;
    std::vector<IOCInfo> extractNetworkIOCs(const std::vector<std::string>& connections) const;
    std::vector<IOCInfo> extractFileIOCs(const std::vector<std::string>& files) const;
    std::vector<IOCInfo> extractProcessIOCs(const std::vector<std::string>& processes) const;

    // Pattern matching
    bool matchesPattern(const std::string& behavior, const std::string& pattern) const;
    [[nodiscard]] std::vector<std::string> findMatchingBehaviors(
        const std::vector<std::string>& behaviors, const std::string& pattern) const;

    // Statistics
    [[nodiscard]] uint64_t getTotalAnalyses() const;
    [[nodiscard]] uint64_t getRuleCount() const;

private:
    std::string generateRuleId();
    void initDefaultRules();

    mutable std::mutex mutex_;
    std::unordered_map<std::string, AnalysisRule> rules_;
    mutable uint64_t totalAnalyses_ = 0;
    int nextRuleId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Sandbox
