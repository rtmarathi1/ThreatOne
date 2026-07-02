#include "siem/DetectionRules.h"

#include <algorithm>

namespace ThreatOne::SIEM {

DetectionRules::DetectionRules()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("DetectionRules")) {
    logger_.info("DetectionRules initialized");
}

std::string DetectionRules::generateRuleId() {
    return "RULE-" + std::to_string(nextRuleId_++);
}

std::string DetectionRules::addRule(const SIEMRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    SIEMRule stored = rule;
    if (stored.id.empty()) {
        stored.id = generateRuleId();
    }
    rules_[stored.id] = stored;
    logger_.info("Added detection rule: id={}, name={}", stored.id, stored.name);
    return stored.id;
}

bool DetectionRules::removeRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.erase(ruleId) > 0;
}

bool DetectionRules::enableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(ruleId);
    if (it != rules_.end()) {
        it->second.enabled = true;
        return true;
    }
    return false;
}

bool DetectionRules::disableRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(ruleId);
    if (it != rules_.end()) {
        it->second.enabled = false;
        return true;
    }
    return false;
}

std::vector<SIEMRule> DetectionRules::getRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SIEMRule> result;
    result.reserve(rules_.size());
    for (const auto& [id, rule] : rules_) {
        result.push_back(rule);
    }
    return result;
}

SIEMRule DetectionRules::getRule(const std::string& ruleId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = rules_.find(ruleId);
    if (it != rules_.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::string> DetectionRules::evaluate(const LogEntry& entry) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::string> matchedRuleIds;
    for (const auto& [id, rule] : rules_) {
        if (!rule.enabled) continue;
        if (matchesCondition(entry, rule.condition)) {
            matchedRuleIds.push_back(id);
        }
    }
    return matchedRuleIds;
}

bool DetectionRules::matchesCondition(const LogEntry& entry,
                                       const std::string& condition) const {
    // Condition format: "field=value" or substring match on message
    auto eqPos = condition.find('=');
    if (eqPos != std::string::npos) {
        std::string field = condition.substr(0, eqPos);
        std::string value = condition.substr(eqPos + 1);

        if (field == "source") return entry.source == value;
        if (field == "severity") return entry.severity == value;
        if (field == "message") {
            return entry.message.find(value) != std::string::npos;
        }

        // Check metadata
        auto it = entry.metadata.find(field);
        if (it != entry.metadata.end()) {
            return it->second == value;
        }
        return false;
    }

    // Simple substring match on message
    return entry.message.find(condition) != std::string::npos;
}

} // namespace ThreatOne::SIEM
