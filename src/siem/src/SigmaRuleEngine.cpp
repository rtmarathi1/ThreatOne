#include "siem/SigmaRuleEngine.h"
#include <mutex>

#include <algorithm>
#include <sstream>
#include <regex>

namespace ThreatOne::SIEM {

SigmaRuleEngine::SigmaRuleEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SigmaRuleEngine")) {
    logger_.info("SigmaRuleEngine initialized");
}

std::string SigmaRuleEngine::generateRuleId() {
    return "SIGMA-" + std::to_string(nextRuleId_++);
}

std::string SigmaRuleEngine::addRule(const SigmaRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    SigmaRule stored = rule;
    if (stored.id.empty()) {
        stored.id = generateRuleId();
    }
    rules_[stored.id] = stored;
    logger_.info("Added Sigma rule: id={}, title={}", stored.id, stored.title);
    return stored.id;
}

bool SigmaRuleEngine::removeRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.erase(ruleId) > 0;
}

std::vector<SigmaRule> SigmaRuleEngine::getRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SigmaRule> result;
    result.reserve(rules_.size());
    for (const auto& [id, rule] : rules_) {
        result.push_back(rule);
    }
    return result;
}

std::vector<SigmaMatch> SigmaRuleEngine::evaluate(const LogEntry& entry) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SigmaMatch> matches;
    for (const auto& [id, rule] : rules_) {
        if (!rule.enabled) continue;
        if (evaluateRule(entry, rule)) {
            SigmaMatch match;
            match.ruleId = rule.id;
            match.ruleTitle = rule.title;
            match.severity = rule.severity;
            // Collect matched fields
            for (const auto& det : rule.detections) {
                for (const auto& fm : det.fieldMatches) {
                    match.matchedFields.push_back(fm.field);
                }
            }
            matches.push_back(match);
        }
    }
    return matches;
}

bool SigmaRuleEngine::evaluateRule(const LogEntry& entry, const SigmaRule& rule) const {
    if (rule.detections.empty()) return false;
    return evaluateCondition(entry, rule);
}

bool SigmaRuleEngine::evaluateCondition(const LogEntry& entry,
                                          const SigmaRule& rule) const {
    // Parse condition DSL: supports "det1 AND det2", "det1 OR det2", "NOT det1"
    // Simple parser for common patterns
    const std::string& condition = rule.condition;

    if (condition.empty()) {
        // If no condition specified, all detections must match (implicit AND)
        for (const auto& det : rule.detections) {
            if (!evaluateDetection(entry, det)) return false;
        }
        return true;
    }

    // Tokenize the condition
    std::istringstream ss(condition);
    std::string token;
    std::vector<std::string> tokens;
    while (ss >> token) {
        tokens.push_back(token);
    }

    if (tokens.empty()) return false;

    // Simple evaluation: handle "sel1 AND sel2", "sel1 OR sel2", "NOT sel1"
    // Find detection by name
    auto findDetection = [&](const std::string& name) -> const SigmaDetection* {
        for (const auto& det : rule.detections) {
            if (det.name == name) return &det;
        }
        return nullptr;
    };

    // Simple single-detection case
    if (tokens.size() == 1) {
        auto* det = findDetection(tokens[0]);
        if (det) return evaluateDetection(entry, *det);
        return false;
    }

    // NOT <detection>
    if (tokens.size() == 2 && tokens[0] == "NOT") {
        auto* det = findDetection(tokens[1]);
        if (det) return !evaluateDetection(entry, *det);
        return false;
    }

    // <det1> AND/OR <det2> (simple two-operand)
    if (tokens.size() >= 3) {
        // Evaluate left-to-right with AND/OR operators
        auto* firstDet = findDetection(tokens[0]);
        bool result = firstDet ? evaluateDetection(entry, *firstDet) : false;

        for (size_t i = 1; i + 1 < tokens.size(); i += 2) {
            const std::string& op = tokens[i];
            const std::string& operand = tokens[i + 1];

            bool negate = false;
            std::string detName = operand;

            // Handle "AND NOT det" pattern
            if (op == "AND" && operand == "NOT" && i + 2 < tokens.size()) {
                negate = true;
                detName = tokens[i + 2];
                i++; // skip the NOT token
            }

            auto* det = findDetection(detName);
            bool detResult = det ? evaluateDetection(entry, *det) : false;
            if (negate) detResult = !detResult;

            if (op == "AND") {
                result = result && detResult;
            } else if (op == "OR") {
                result = result || detResult;
            }
        }
        return result;
    }

    return false;
}

bool SigmaRuleEngine::evaluateDetection(const LogEntry& entry,
                                          const SigmaDetection& detection) const {
    // All field matches in a detection must match (AND logic within detection)
    for (const auto& fm : detection.fieldMatches) {
        std::string fieldValue = getFieldValue(entry, fm.field);
        if (!fieldMatchesValue(fieldValue, fm)) {
            return false;
        }
    }
    return !detection.fieldMatches.empty();
}

bool SigmaRuleEngine::fieldMatchesValue(const std::string& fieldValue,
                                          const SigmaFieldMatch& match) const {
    if (fieldValue.empty() && !match.values.empty()) return false;

    for (const auto& pattern : match.values) {
        if (match.isRegex) {
            try {
                std::regex re(pattern, match.caseSensitive ?
                    std::regex_constants::ECMAScript :
                    std::regex_constants::icase);
                if (std::regex_search(fieldValue, re)) return true;
            } catch (...) {
                // Invalid regex, try substring match
                if (fieldValue.find(pattern) != std::string::npos) return true;
            }
        } else {
            // Simple match: support wildcards (*) at start/end
            if (pattern == "*") return true;

            std::string compareField = fieldValue;
            std::string comparePattern = pattern;

            if (!match.caseSensitive) {
                std::transform(compareField.begin(), compareField.end(),
                             compareField.begin(), ::tolower);
                std::transform(comparePattern.begin(), comparePattern.end(),
                             comparePattern.begin(), ::tolower);
            }

            if (comparePattern.front() == '*' && comparePattern.back() == '*') {
                // Contains
                std::string sub = comparePattern.substr(1, comparePattern.size() - 2);
                if (compareField.find(sub) != std::string::npos) return true;
            } else if (comparePattern.front() == '*') {
                // Ends with
                std::string suffix = comparePattern.substr(1);
                if (compareField.size() >= suffix.size() &&
                    compareField.compare(compareField.size() - suffix.size(),
                                        suffix.size(), suffix) == 0) {
                    return true;
                }
            } else if (comparePattern.back() == '*') {
                // Starts with
                std::string prefix = comparePattern.substr(0, comparePattern.size() - 1);
                if (compareField.compare(0, prefix.size(), prefix) == 0) return true;
            } else {
                // Exact match
                if (compareField == comparePattern) return true;
            }
        }
    }
    return false;
}

std::string SigmaRuleEngine::getFieldValue(const LogEntry& entry,
                                             const std::string& field) const {
    if (field == "source") return entry.source;
    if (field == "message") return entry.message;
    if (field == "severity") return entry.severity;
    if (field == "timestamp") return entry.timestamp;

    auto it = entry.metadata.find(field);
    if (it != entry.metadata.end()) {
        return it->second;
    }
    return "";
}

} // namespace ThreatOne::SIEM
