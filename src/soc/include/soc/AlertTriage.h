#pragma once

#include "soc/ISOCManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <deque>

namespace ThreatOne::SOC {

enum class AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

enum class AlertStatus {
    New,
    Triaged,
    Assigned,
    Investigating,
    Resolved,
    Dismissed
};

struct TriageAlert {
    std::string id;
    std::string title;
    std::string source;
    std::string description;
    AlertSeverity severity = AlertSeverity::Medium;
    AlertStatus status = AlertStatus::New;
    double score = 0.0;
    std::string assignedTo;
    std::string groupId;
    std::string createdAt;
    std::string caseId;  // linked case if any
    std::vector<std::string> tags;
};

struct TriageRule {
    std::string id;
    std::string name;
    std::string condition;  // simplified condition string
    AlertSeverity targetSeverity = AlertSeverity::Medium;
    double scoreModifier = 0.0;
    bool autoAssign = false;
    std::string assignTo;
};

class AlertTriage {
public:
    AlertTriage();
    ~AlertTriage() = default;

    // Alert ingestion and triage
    std::string ingestAlert(const TriageAlert& alert);
    bool triageAlert(const std::string& alertId);
    bool assignAlert(const std::string& alertId, const std::string& analystId);
    bool dismissAlert(const std::string& alertId, const std::string& reason);
    bool resolveAlert(const std::string& alertId);

    // Alert queries
    [[nodiscard]] TriageAlert getAlert(const std::string& alertId) const;
    [[nodiscard]] std::vector<TriageAlert> getAlertsByStatus(AlertStatus status) const;
    [[nodiscard]] std::vector<TriageAlert> getAlertsBySeverity(AlertSeverity severity) const;
    [[nodiscard]] std::vector<TriageAlert> getAlertQueue() const;
    [[nodiscard]] bool alertExists(const std::string& alertId) const;

    // Triage rules
    std::string addTriageRule(const TriageRule& rule);
    bool removeTriageRule(const std::string& ruleId);
    [[nodiscard]] std::vector<TriageRule> getTriageRules() const;

    // Deduplication and grouping
    [[nodiscard]] std::string findDuplicate(const TriageAlert& alert) const;
    bool groupAlerts(const std::string& alertId1, const std::string& alertId2);

    // Scoring
    [[nodiscard]] double computeScore(const TriageAlert& alert) const;

    // Statistics
    [[nodiscard]] size_t getAlertCount() const;
    [[nodiscard]] size_t getPendingAlertCount() const;

    // Auto-assignment based on analyst workload
    [[nodiscard]] std::string suggestAssignee(
        const std::vector<std::string>& analysts,
        const std::vector<CaseInfo>& cases) const;

private:
    void applyTriageRules(TriageAlert& alert);

    mutable std::mutex mutex_;
    std::map<std::string, TriageAlert> alerts_;
    std::vector<TriageRule> triageRules_;
    std::deque<std::string> alertQueue_;  // ordered by score descending
    int nextAlertId_ = 1;
    int nextRuleId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
