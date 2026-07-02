#include "telemetry/PrivacyFilter.h"
#include <optional>
#include <mutex>

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Telemetry {

PrivacyFilter::PrivacyFilter()
    : logger_(Core::Logger::instance().getModuleLogger("PrivacyFilter")) {
    initDefaultRules();
    logger_.info("PrivacyFilter initialized with {} rules", rules_.size());
}

std::string PrivacyFilter::generateRuleId() {
    return "PRULE-" + std::to_string(nextRuleId_++);
}

void PrivacyFilter::initDefaultRules() {
    FilterRule emailRule;
    emailRule.id = "PRULE-DEFAULT-EMAIL";
    emailRule.name = "Email Filter";
    emailRule.type = PIIType::Email;
    emailRule.pattern = "@";
    emailRule.replacement = "[EMAIL_REDACTED]";
    rules_[emailRule.id] = emailRule;

    FilterRule ipRule;
    ipRule.id = "PRULE-DEFAULT-IP";
    ipRule.name = "IP Address Filter";
    ipRule.type = PIIType::IPAddress;
    ipRule.pattern = "\\d+\\.\\d+\\.\\d+\\.\\d+";
    ipRule.replacement = "[IP_REDACTED]";
    rules_[ipRule.id] = ipRule;

    FilterRule ssnRule;
    ssnRule.id = "PRULE-DEFAULT-SSN";
    ssnRule.name = "SSN Filter";
    ssnRule.type = PIIType::SSN;
    ssnRule.pattern = "\\d{3}-\\d{2}-\\d{4}";
    ssnRule.replacement = "[SSN_REDACTED]";
    rules_[ssnRule.id] = ssnRule;
}

bool PrivacyFilter::matchesPattern(const std::string& value, const std::string& pattern) const {
    // Simple substring-based matching for patterns without regex chars
    // For patterns with @ or digit patterns, use substring matching
    if (pattern == "@") {
        return value.find('@') != std::string::npos;
    }
    return value.find(pattern) != std::string::npos;
}

std::string PrivacyFilter::addFilterRule(const FilterRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = generateRuleId();
    FilterRule newRule = rule;
    newRule.id = id;
    rules_[id] = newRule;
    logger_.info("Added filter rule: {} ({})", newRule.name, id);
    return id;
}

bool PrivacyFilter::removeFilterRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(ruleId);
    if (it == rules_.end()) return false;
    rules_.erase(it);
    return true;
}

bool PrivacyFilter::enableRule(const std::string& ruleId, bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(ruleId);
    if (it == rules_.end()) return false;
    it->second.enabled = enabled;
    return true;
}

std::vector<FilterRule> PrivacyFilter::getFilterRules() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<FilterRule> result;
    result.reserve(rules_.size());
    for (const auto& [id, rule] : rules_) {
        result.push_back(rule);
    }
    return result;
}

std::optional<FilterRule> PrivacyFilter::getRule(const std::string& ruleId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = rules_.find(ruleId);
    if (it == rules_.end()) return std::nullopt;
    return it->second;
}

FilterResult PrivacyFilter::filterValue(const std::string& value) const {
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_.totalProcessed;

    FilterResult result;
    result.originalValue = value;
    result.filteredValue = value;
    result.modified = false;

    for (const auto& [id, rule] : rules_) {
        if (!rule.enabled) continue;

        if (matchesPattern(value, rule.pattern)) {
            result.filteredValue = rule.replacement;
            result.modified = true;
            result.matchedRules.push_back(rule.name);
            ++stats_.totalFiltered;
            ++stats_.totalPIIDetected;
            break;  // Apply first matching rule
        }
    }

    return result;
}

TelemetryEvent PrivacyFilter::filterEvent(const TelemetryEvent& event) const {
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_.totalProcessed;

    TelemetryEvent filtered = event;

    // Filter properties
    for (auto& [key, value] : filtered.properties) {
        if (blockedFields_.count(key) > 0) {
            value = "[BLOCKED]";
            ++stats_.totalFiltered;
            continue;
        }

        if (!allowedFields_.empty() && allowedFields_.count(key) == 0) {
            // Not in allowlist - check for PII
            for (const auto& [ruleId, rule] : rules_) {
                if (!rule.enabled) continue;
                if (matchesPattern(value, rule.pattern)) {
                    value = rule.replacement;
                    ++stats_.totalFiltered;
                    ++stats_.totalPIIDetected;
                    break;
                }
            }
        }
    }

    return filtered;
}

std::string PrivacyFilter::filterString(const std::string& input) const {
    auto result = filterValue(input);
    return result.filteredValue;
}

void PrivacyFilter::addAllowedField(const std::string& fieldName) {
    std::lock_guard<std::mutex> lock(mutex_);
    allowedFields_.insert(fieldName);
}

void PrivacyFilter::removeAllowedField(const std::string& fieldName) {
    std::lock_guard<std::mutex> lock(mutex_);
    allowedFields_.erase(fieldName);
}

void PrivacyFilter::addBlockedField(const std::string& fieldName) {
    std::lock_guard<std::mutex> lock(mutex_);
    blockedFields_.insert(fieldName);
}

void PrivacyFilter::removeBlockedField(const std::string& fieldName) {
    std::lock_guard<std::mutex> lock(mutex_);
    blockedFields_.erase(fieldName);
}

bool PrivacyFilter::isFieldAllowed(const std::string& fieldName) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (blockedFields_.count(fieldName) > 0) return false;
    if (allowedFields_.empty()) return true;
    return allowedFields_.count(fieldName) > 0;
}

bool PrivacyFilter::setDataRetentionDays(uint32_t days) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (days == 0) return false;
    dataRetentionDays_ = days;
    return true;
}

uint32_t PrivacyFilter::getDataRetentionDays() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dataRetentionDays_;
}

FilterStats PrivacyFilter::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

uint64_t PrivacyFilter::getTotalFiltered() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.totalFiltered;
}

void PrivacyFilter::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = FilterStats{};
}

} // namespace ThreatOne::Telemetry
