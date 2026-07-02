#include "sandbox/SandboxAnalyzer.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Sandbox {

SandboxAnalyzer::SandboxAnalyzer()
    : logger_(Core::Logger::instance().getModuleLogger("SandboxAnalyzer")) {
    initDefaultRules();
    logger_.info("SandboxAnalyzer initialized with {} rules", rules_.size());
}

std::string SandboxAnalyzer::generateRuleId() {
    return "ARULE-" + std::to_string(nextRuleId_++);
}

void SandboxAnalyzer::initDefaultRules() {
    AnalysisRule r1;
    r1.id = "ARULE-DEFAULT-1";
    r1.name = "Process Creation";
    r1.description = "Detects suspicious process creation";
    r1.severityWeight = 5;
    r1.behaviorPattern = "cmd.exe";
    rules_[r1.id] = r1;

    AnalysisRule r2;
    r2.id = "ARULE-DEFAULT-2";
    r2.name = "PowerShell Execution";
    r2.description = "Detects PowerShell usage";
    r2.severityWeight = 7;
    r2.behaviorPattern = "powershell";
    rules_[r2.id] = r2;

    AnalysisRule r3;
    r3.id = "ARULE-DEFAULT-3";
    r3.name = "Registry Modification";
    r3.description = "Detects registry modifications";
    r3.severityWeight = 6;
    r3.behaviorPattern = "registry";
    rules_[r3.id] = r3;

    AnalysisRule r4;
    r4.id = "ARULE-DEFAULT-4";
    r4.name = "Network Communication";
    r4.description = "Detects outbound network connections";
    r4.severityWeight = 4;
    r4.behaviorPattern = "connect";
    rules_[r4.id] = r4;
}

std::string SandboxAnalyzer::addAnalysisRule(const AnalysisRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateRuleId();
    AnalysisRule newRule = rule;
    newRule.id = id;
    rules_[id] = newRule;
    logger_.info("Added analysis rule: {} ({})", newRule.name, id);
    return id;
}

bool SandboxAnalyzer::removeAnalysisRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(ruleId);
    if (it == rules_.end()) {
        return false;
    }

    rules_.erase(it);
    return true;
}

bool SandboxAnalyzer::enableRule(const std::string& ruleId, bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(ruleId);
    if (it == rules_.end()) {
        return false;
    }

    it->second.enabled = enabled;
    return true;
}

std::vector<AnalysisRule> SandboxAnalyzer::getAnalysisRules() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<AnalysisRule> result;
    result.reserve(rules_.size());
    for (const auto& [id, rule] : rules_) {
        result.push_back(rule);
    }
    return result;
}

std::optional<AnalysisRule> SandboxAnalyzer::getRule(const std::string& ruleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(ruleId);
    if (it == rules_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool SandboxAnalyzer::matchesPattern(const std::string& behavior, const std::string& pattern) const {
    // Simple substring matching
    return behavior.find(pattern) != std::string::npos;
}

std::vector<std::string> SandboxAnalyzer::findMatchingBehaviors(
    const std::vector<std::string>& behaviors, const std::string& pattern) const {
    std::vector<std::string> matches;
    for (const auto& b : behaviors) {
        if (matchesPattern(b, pattern)) {
            matches.push_back(b);
        }
    }
    return matches;
}

VerdictDetails SandboxAnalyzer::analyzeBehaviors(const std::vector<std::string>& behaviors) const {
    std::lock_guard<std::mutex> lock(mutex_);
    ++totalAnalyses_;

    VerdictDetails details;

    if (behaviors.empty()) {
        details.verdict = SandboxVerdict::Clean;
        details.confidenceScore = 90.0;
        details.threatScore = 0.0;
        details.rationale = "No suspicious behaviors detected";
        return details;
    }

    double totalWeight = 0.0;
    int matchCount = 0;

    for (const auto& [id, rule] : rules_) {
        if (!rule.enabled) continue;

        for (const auto& behavior : behaviors) {
            if (matchesPattern(behavior, rule.behaviorPattern)) {
                totalWeight += rule.severityWeight;
                ++matchCount;
                details.matchedRules.push_back(rule.name);
                details.indicators.push_back(behavior);
                break;  // Only count each rule once
            }
        }
    }

    // Compute threat score based on matched rule weights and behavior count
    details.threatScore = std::min(100.0, (totalWeight * 10.0) + (static_cast<double>(behaviors.size()) * 5.0));
    details.confidenceScore = std::min(100.0, 50.0 + (matchCount * 15.0));

    if (details.threatScore >= 70.0) {
        details.verdict = SandboxVerdict::Malicious;
        details.rationale = "Multiple high-severity indicators detected";
    } else if (details.threatScore >= 30.0 || behaviors.size() <= 2) {
        details.verdict = SandboxVerdict::Suspicious;
        details.rationale = "Some suspicious behaviors detected";
    } else {
        details.verdict = SandboxVerdict::Clean;
        details.rationale = "Low threat indicators";
    }

    return details;
}

SandboxVerdict SandboxAnalyzer::computeVerdict(const std::vector<std::string>& behaviors) const {
    if (behaviors.empty()) {
        return SandboxVerdict::Clean;
    }
    if (behaviors.size() <= 2) {
        return SandboxVerdict::Suspicious;
    }
    return SandboxVerdict::Malicious;
}

double SandboxAnalyzer::computeThreatScore(const std::vector<std::string>& behaviors) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (behaviors.empty()) {
        return 0.0;
    }

    double totalWeight = 0.0;
    for (const auto& [id, rule] : rules_) {
        if (!rule.enabled) continue;
        for (const auto& behavior : behaviors) {
            if (matchesPattern(behavior, rule.behaviorPattern)) {
                totalWeight += rule.severityWeight;
                break;
            }
        }
    }

    return std::min(100.0, totalWeight * 10.0 + static_cast<double>(behaviors.size()) * 5.0);
}

std::vector<IOCInfo> SandboxAnalyzer::extractIOCs(const BehaviorReport& report) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<IOCInfo> iocs;

    auto networkIOCs = extractNetworkIOCs(report.networkConnections);
    iocs.insert(iocs.end(), networkIOCs.begin(), networkIOCs.end());

    auto fileIOCs = extractFileIOCs(report.droppedFiles);
    iocs.insert(iocs.end(), fileIOCs.begin(), fileIOCs.end());

    auto processIOCs = extractProcessIOCs(report.processesCreated);
    iocs.insert(iocs.end(), processIOCs.begin(), processIOCs.end());

    // Registry IOCs
    for (const auto& reg : report.registryChanges) {
        IOCInfo ioc;
        ioc.type = "registry";
        ioc.value = reg;
        ioc.description = "Registry modification during detonation";
        ioc.confidence = "medium";
        iocs.push_back(ioc);
    }

    return iocs;
}

std::vector<IOCInfo> SandboxAnalyzer::extractNetworkIOCs(
    const std::vector<std::string>& connections) const {
    std::vector<IOCInfo> iocs;
    for (const auto& conn : connections) {
        IOCInfo ioc;
        ioc.type = "ip";
        ioc.value = conn;
        ioc.description = "Network connection observed during detonation";
        ioc.confidence = "high";
        iocs.push_back(ioc);
    }
    return iocs;
}

std::vector<IOCInfo> SandboxAnalyzer::extractFileIOCs(const std::vector<std::string>& files) const {
    std::vector<IOCInfo> iocs;
    for (const auto& file : files) {
        IOCInfo ioc;
        ioc.type = "file_hash";
        ioc.value = file;
        ioc.description = "File dropped during detonation";
        ioc.confidence = "high";
        iocs.push_back(ioc);
    }
    return iocs;
}

std::vector<IOCInfo> SandboxAnalyzer::extractProcessIOCs(
    const std::vector<std::string>& processes) const {
    std::vector<IOCInfo> iocs;
    for (const auto& proc : processes) {
        IOCInfo ioc;
        ioc.type = "process";
        ioc.value = proc;
        ioc.description = "Process created during detonation";
        ioc.confidence = "medium";
        iocs.push_back(ioc);
    }
    return iocs;
}

uint64_t SandboxAnalyzer::getTotalAnalyses() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalAnalyses_;
}

uint64_t SandboxAnalyzer::getRuleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
}

} // namespace ThreatOne::Sandbox
