#pragma once

#include "telemetry/ITelemetryManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <cstdint>

namespace ThreatOne::Telemetry {

enum class PIIType {
    Email,
    IPAddress,
    PhoneNumber,
    CreditCard,
    SSN,
    Name,
    Custom
};

struct FilterRule {
    std::string id;
    std::string name;
    PIIType type = PIIType::Custom;
    std::string pattern;
    std::string replacement = "[REDACTED]";
    bool enabled = true;
};

struct FilterResult {
    std::string originalValue;
    std::string filteredValue;
    bool modified = false;
    std::vector<std::string> matchedRules;
};

struct FilterStats {
    uint64_t totalProcessed = 0;
    uint64_t totalFiltered = 0;
    uint64_t totalPIIDetected = 0;
    std::unordered_map<std::string, uint64_t> detectionsByType;
};

class PrivacyFilter {
public:
    PrivacyFilter();
    ~PrivacyFilter() = default;

    // Rule management
    std::string addFilterRule(const FilterRule& rule);
    bool removeFilterRule(const std::string& ruleId);
    bool enableRule(const std::string& ruleId, bool enabled);
    [[nodiscard]] std::vector<FilterRule> getFilterRules() const;
    [[nodiscard]] std::optional<FilterRule> getRule(const std::string& ruleId) const;

    // Filtering
    FilterResult filterValue(const std::string& value) const;
    TelemetryEvent filterEvent(const TelemetryEvent& event) const;
    std::string filterString(const std::string& input) const;

    // Allowlist/blocklist
    void addAllowedField(const std::string& fieldName);
    void removeAllowedField(const std::string& fieldName);
    void addBlockedField(const std::string& fieldName);
    void removeBlockedField(const std::string& fieldName);
    [[nodiscard]] bool isFieldAllowed(const std::string& fieldName) const;

    // Data minimization
    bool setDataRetentionDays(uint32_t days);
    [[nodiscard]] uint32_t getDataRetentionDays() const;

    // Statistics
    [[nodiscard]] FilterStats getStats() const;
    [[nodiscard]] uint64_t getTotalFiltered() const;
    void resetStats();

private:
    std::string generateRuleId();
    void initDefaultRules();
    bool matchesPattern(const std::string& value, const std::string& pattern) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, FilterRule> rules_;
    std::unordered_set<std::string> allowedFields_;
    std::unordered_set<std::string> blockedFields_;
    mutable FilterStats stats_;
    uint32_t dataRetentionDays_ = 90;
    int nextRuleId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Telemetry
