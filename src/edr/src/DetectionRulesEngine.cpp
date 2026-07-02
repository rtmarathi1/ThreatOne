#include "edr/DetectionRulesEngine.h"

#include <nlohmann/json.hpp>
#include <regex>
#include <sstream>
#include <algorithm>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::EDR {

DetectionRulesEngine::DetectionRulesEngine()
    : logger_(Core::Logger::instance().getModuleLogger("DetectionRulesEngine"))
{
    logger_.info("DetectionRulesEngine initialized");
}

bool DetectionRulesEngine::loadRules(const std::string& jsonString) {
    try {
        auto json = nlohmann::json::parse(jsonString);

        std::lock_guard lock(mutex_);

        // Collect rule objects to process
        std::vector<nlohmann::json> ruleArray;
        if (json.is_array()) {
            const auto& arr = json.get_array();
            for (const auto& item : arr) {
                ruleArray.push_back(item);
            }
        } else if (json.is_object()) {
            ruleArray.push_back(json);
        } else {
            logger_.error("Invalid JSON format for rules");
            return false;
        }

        for (const auto& ruleJson : ruleArray) {
            DetectionRule rule;
            rule.id = ruleJson.value("id", "");
            rule.name = ruleJson.value("name", "");
            rule.description = ruleJson.value("description", "");
            rule.severity = ruleJson.value("severity", "info");
            rule.logic = ruleJson.value("logic", "AND");

            if (ruleJson.contains("conditions") && ruleJson["conditions"].is_array()) {
                const auto& condArray = ruleJson["conditions"].get_array();
                for (size_t i = 0; i < condArray.size(); i++) {
                    const auto& condJson = condArray[i];
                    RuleCondition cond;
                    cond.field = condJson.value("field", "");
                    cond.op = condJson.value("operator", "equals");
                    cond.value = condJson.value("value", "");
                    rule.conditions.push_back(cond);
                }
            }

            if (ruleJson.contains("actions") && ruleJson["actions"].is_array()) {
                const auto& actArray = ruleJson["actions"].get_array();
                for (const auto& act : actArray) {
                    if (act.is_string()) {
                        rule.actions.push_back(act.get<std::string>());
                    }
                }
            }

            rules_.push_back(rule);
            compileRegexPatterns(rule);
        }

        logger_.info("Loaded {} rules from JSON", ruleArray.size());
        return true;
    } catch (const std::exception& e) {
        logger_.error("Failed to parse rules JSON: {}", e.what());
        return false;
    }
}

void DetectionRulesEngine::addRule(const DetectionRule& rule) {
    std::lock_guard lock(mutex_);
    rules_.push_back(rule);
    compileRegexPatterns(rule);
    logger_.debug("Added rule: {} ({})", rule.name, rule.id);
}

std::vector<RuleMatch> DetectionRulesEngine::evaluate(const EDREvent& event) const {
    std::lock_guard lock(mutex_);
    std::vector<RuleMatch> matches;

    for (const auto& rule : rules_) {
        bool ruleMatches = false;
        std::string matchedField;
        std::string matchedValue;

        if (rule.logic == "OR") {
            // OR logic: any condition matches
            for (const auto& condition : rule.conditions) {
                if (evaluateCondition(condition, event)) {
                    ruleMatches = true;
                    matchedField = condition.field;
                    matchedValue = getEventField(event, condition.field);
                    break;
                }
            }
        } else {
            // AND logic (default): all conditions must match
            bool allMatch = !rule.conditions.empty();
            for (const auto& condition : rule.conditions) {
                if (!evaluateCondition(condition, event)) {
                    allMatch = false;
                    break;
                }
                matchedField = condition.field;
                matchedValue = getEventField(event, condition.field);
            }
            ruleMatches = allMatch;
        }

        if (ruleMatches) {
            RuleMatch match;
            match.ruleId = rule.id;
            match.ruleName = rule.name;
            match.severity = rule.severity;
            match.actions = rule.actions;
            match.matchedField = matchedField;
            match.matchedValue = matchedValue;
            matches.push_back(match);
        }
    }

    return matches;
}

size_t DetectionRulesEngine::getRuleCount() const {
    std::lock_guard lock(mutex_);
    return rules_.size();
}

std::vector<DetectionRule> DetectionRulesEngine::getRules() const {
    std::lock_guard lock(mutex_);
    return rules_;
}

void DetectionRulesEngine::removeRule(const std::string& ruleId) {
    std::lock_guard lock(mutex_);
    rules_.erase(
        std::remove_if(rules_.begin(), rules_.end(),
                       [&ruleId](const DetectionRule& r) { return r.id == ruleId; }),
        rules_.end());
}

void DetectionRulesEngine::clearRules() {
    std::lock_guard lock(mutex_);
    rules_.clear();
    compiledRegexCache_.clear();
}

bool DetectionRulesEngine::evaluateCondition(const RuleCondition& condition, const EDREvent& event) const {
    std::string fieldValue = getEventField(event, condition.field);

    if (condition.op == "equals") {
        return fieldValue == condition.value;
    } else if (condition.op == "contains") {
        return fieldValue.find(condition.value) != std::string::npos;
    } else if (condition.op == "regex") {
        try {
            auto it = compiledRegexCache_.find(condition.value);
            if (it != compiledRegexCache_.end()) {
                return std::regex_search(fieldValue, it->second);
            }
            // Fallback: compile on the fly if not cached (shouldn't happen normally)
            std::regex re(condition.value);
            return std::regex_search(fieldValue, re);
        } catch (...) {
            return false;
        }
    } else if (condition.op == "greater_than") {
        try {
            double fieldNum = std::stod(fieldValue);
            double condNum = std::stod(condition.value);
            return fieldNum > condNum;
        } catch (...) {
            return false;
        }
    } else if (condition.op == "less_than") {
        try {
            double fieldNum = std::stod(fieldValue);
            double condNum = std::stod(condition.value);
            return fieldNum < condNum;
        } catch (...) {
            return false;
        }
    } else if (condition.op == "in_list") {
        // Value is comma-separated list
        std::istringstream stream(condition.value);
        std::string item;
        while (std::getline(stream, item, ',')) {
            // Trim whitespace
            auto start = item.find_first_not_of(" \t");
            auto end = item.find_last_not_of(" \t");
            if (start != std::string::npos) {
                item = item.substr(start, end - start + 1);
            }
            if (item == fieldValue) {
                return true;
            }
        }
        return false;
    }

    return false;
}

std::string DetectionRulesEngine::getEventField(const EDREvent& event, const std::string& field) const {
    if (field == "type") return event.type;
    if (field == "source") return event.source;
    if (field == "path") return event.path;
    if (field == "details") return event.details;
    if (field == "pid") return std::to_string(event.pid);
    if (field == "entropy") return std::to_string(event.entropy);
    if (field == "dataSize") return std::to_string(event.dataSize);
    return "";
}

void DetectionRulesEngine::compileRegexPatterns(const DetectionRule& rule) {
    for (const auto& condition : rule.conditions) {
        if (condition.op == "regex" && !condition.value.empty()) {
            if (compiledRegexCache_.find(condition.value) == compiledRegexCache_.end()) {
                try {
                    compiledRegexCache_.emplace(condition.value, std::regex(condition.value));
                } catch (const std::regex_error& e) {
                    logger_.warn("Failed to compile regex pattern '{}': {}", condition.value, e.what());
                }
            }
        }
    }
}

} // namespace ThreatOne::EDR
