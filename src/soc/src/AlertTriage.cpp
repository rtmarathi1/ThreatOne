#include "soc/AlertTriage.h"
#include <mutex>

#include <algorithm>

namespace ThreatOne::SOC {

AlertTriage::AlertTriage()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("AlertTriage")) {
    logger_.info("AlertTriage initialized");
}

std::string AlertTriage::ingestAlert(const TriageAlert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "ALR-" + std::to_string(nextAlertId_++);
    TriageAlert stored = alert;
    stored.id = id;
    stored.status = AlertStatus::New;
    stored.score = computeScore(stored);

    // Apply triage rules
    applyTriageRules(stored);

    alerts_[id] = stored;
    alertQueue_.push_back(id);

    logger_.info("Ingested alert: id={}, title={}, score={:.1f}",
                 id, alert.title, stored.score);
    return id;
}

bool AlertTriage::triageAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = alerts_.find(alertId);
    if (it == alerts_.end()) {
        return false;
    }

    it->second.status = AlertStatus::Triaged;
    logger_.info("Triaged alert {}", alertId);
    return true;
}

bool AlertTriage::assignAlert(const std::string& alertId, const std::string& analystId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = alerts_.find(alertId);
    if (it == alerts_.end()) {
        return false;
    }

    it->second.assignedTo = analystId;
    it->second.status = AlertStatus::Assigned;
    logger_.info("Assigned alert {} to {}", alertId, analystId);
    return true;
}

bool AlertTriage::dismissAlert(const std::string& alertId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = alerts_.find(alertId);
    if (it == alerts_.end()) {
        return false;
    }

    it->second.status = AlertStatus::Dismissed;
    logger_.info("Dismissed alert {}: {}", alertId, reason);
    return true;
}

bool AlertTriage::resolveAlert(const std::string& alertId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = alerts_.find(alertId);
    if (it == alerts_.end()) {
        return false;
    }

    it->second.status = AlertStatus::Resolved;
    logger_.info("Resolved alert {}", alertId);
    return true;
}

TriageAlert AlertTriage::getAlert(const std::string& alertId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = alerts_.find(alertId);
    if (it != alerts_.end()) {
        return it->second;
    }
    return {};
}

std::vector<TriageAlert> AlertTriage::getAlertsByStatus(AlertStatus status) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<TriageAlert> result;
    for (const auto& [id, alert] : alerts_) {
        if (alert.status == status) {
            result.push_back(alert);
        }
    }
    return result;
}

std::vector<TriageAlert> AlertTriage::getAlertsBySeverity(AlertSeverity severity) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<TriageAlert> result;
    for (const auto& [id, alert] : alerts_) {
        if (alert.severity == severity) {
            result.push_back(alert);
        }
    }
    return result;
}

std::vector<TriageAlert> AlertTriage::getAlertQueue() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<TriageAlert> result;
    for (const auto& id : alertQueue_) {
        auto it = alerts_.find(id);
        if (it != alerts_.end() && it->second.status == AlertStatus::New) {
            result.push_back(it->second);
        }
    }
    return result;
}

bool AlertTriage::alertExists(const std::string& alertId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return alerts_.find(alertId) != alerts_.end();
}

std::string AlertTriage::addTriageRule(const TriageRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "TR-" + std::to_string(nextRuleId_++);
    TriageRule stored = rule;
    stored.id = id;
    triageRules_.push_back(stored);

    logger_.info("Added triage rule: id={}, name={}", id, rule.name);
    return id;
}

bool AlertTriage::removeTriageRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(triageRules_.begin(), triageRules_.end(),
        [&ruleId](const TriageRule& r) { return r.id == ruleId; });

    if (it == triageRules_.end()) {
        return false;
    }

    triageRules_.erase(it);
    logger_.info("Removed triage rule {}", ruleId);
    return true;
}

std::vector<TriageRule> AlertTriage::getTriageRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return triageRules_;
}

std::string AlertTriage::findDuplicate(const TriageAlert& alert) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& [id, existing] : alerts_) {
        if (existing.title == alert.title &&
            existing.source == alert.source &&
            existing.status != AlertStatus::Resolved &&
            existing.status != AlertStatus::Dismissed) {
            return id;
        }
    }
    return "";
}

bool AlertTriage::groupAlerts(const std::string& alertId1, const std::string& alertId2) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it1 = alerts_.find(alertId1);
    auto it2 = alerts_.find(alertId2);

    if (it1 == alerts_.end() || it2 == alerts_.end()) {
        return false;
    }

    // Group by assigning the same group ID
    std::string groupId = it1->second.groupId.empty() ? alertId1 : it1->second.groupId;
    it1->second.groupId = groupId;
    it2->second.groupId = groupId;

    logger_.info("Grouped alerts {} and {} under group {}", alertId1, alertId2, groupId);
    return true;
}

double AlertTriage::computeScore(const TriageAlert& alert) const {
    // Base score from severity
    double score = 0.0;
    switch (alert.severity) {
        case AlertSeverity::Info: score = 10.0; break;
        case AlertSeverity::Low: score = 30.0; break;
        case AlertSeverity::Medium: score = 50.0; break;
        case AlertSeverity::High: score = 75.0; break;
        case AlertSeverity::Critical: score = 95.0; break;
    }

    // Boost if has description
    if (!alert.description.empty()) {
        score += 2.0;
    }

    // Cap at 100
    if (score > 100.0) score = 100.0;

    return score;
}

size_t AlertTriage::getAlertCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return alerts_.size();
}

size_t AlertTriage::getPendingAlertCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, alert] : alerts_) {
        if (alert.status == AlertStatus::New || alert.status == AlertStatus::Triaged) {
            count++;
        }
    }
    return count;
}

std::string AlertTriage::suggestAssignee(
    const std::vector<std::string>& analysts,
    const std::vector<CaseInfo>& cases) const {

    if (analysts.empty()) {
        return "";
    }

    // Find analyst with lowest workload
    std::map<std::string, size_t> workload;
    for (const auto& analyst : analysts) {
        workload[analyst] = 0;
    }

    for (const auto& c : cases) {
        if (!c.assignee.empty() && c.status != CaseStatus::Closed) {
            if (workload.find(c.assignee) != workload.end()) {
                workload[c.assignee]++;
            }
        }
    }

    std::string leastBusy = analysts[0];
    size_t minLoad = workload[leastBusy];

    for (const auto& [analyst, load] : workload) {
        if (load < minLoad) {
            minLoad = load;
            leastBusy = analyst;
        }
    }

    return leastBusy;
}

void AlertTriage::applyTriageRules(TriageAlert& alert) {
    for (const auto& rule : triageRules_) {
        // Simple condition matching
        bool matches = false;
        if (rule.condition == "severity=critical" &&
            alert.severity == AlertSeverity::Critical) {
            matches = true;
        } else if (rule.condition == "severity=high" &&
                   alert.severity == AlertSeverity::High) {
            matches = true;
        } else if (!rule.condition.empty() &&
                   alert.source.find(rule.condition) != std::string::npos) {
            matches = true;
        }

        if (matches) {
            alert.score += rule.scoreModifier;
            if (rule.autoAssign && !rule.assignTo.empty()) {
                alert.assignedTo = rule.assignTo;
                alert.status = AlertStatus::Assigned;
            }
        }
    }
}

} // namespace ThreatOne::SOC
