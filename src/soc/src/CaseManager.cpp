#include "soc/CaseManager.h"

#include <algorithm>

namespace ThreatOne::SOC {

CaseManager::CaseManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("CaseManager")) {
    logger_.info("CaseManager initialized");
}

std::string CaseManager::createCase(const CaseInfo& caseInfo) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "CASE-" + std::to_string(nextCaseId_++);
    CaseInfo stored = caseInfo;
    stored.id = id;
    stored.status = CaseStatus::Open;
    cases_[id] = stored;

    logger_.info("Created case: id={}, title={}", id, caseInfo.title);

    // Publish SecurityEvent via EventBus for cross-module notification
    Core::SecurityEvent event(
        Core::SecurityEvent::Type::Anomaly,
        Core::SecurityEvent::Severity::Medium,
        "SOC case created: " + caseInfo.title);
    event.setSource("CaseManager");
    event.setData("caseId", id);
    Core::EventBus::instance().publish(event);

    return id;
}

bool CaseManager::assignCase(const std::string& caseId, const std::string& analystId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cases_.find(caseId);
    if (it == cases_.end()) {
        logger_.warn("assignCase failed: case {} not found", caseId);
        return false;
    }

    it->second.assignee = analystId;
    logger_.info("Assigned case {} to analyst {}", caseId, analystId);
    return true;
}

bool CaseManager::escalate(const std::string& caseId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cases_.find(caseId);
    if (it == cases_.end()) {
        logger_.warn("escalate failed: case {} not found", caseId);
        return false;
    }

    it->second.status = CaseStatus::Escalated;
    it->second.escalationReason = reason;
    logger_.info("Escalated case {}: {}", caseId, reason);

    // Publish SecurityEvent via EventBus for cross-module notification
    Core::SecurityEvent event(
        Core::SecurityEvent::Type::PolicyViolation,
        Core::SecurityEvent::Severity::High,
        "SOC case escalated: " + caseId + " - " + reason);
    event.setSource("CaseManager");
    event.setData("caseId", caseId);
    event.setData("reason", reason);
    Core::EventBus::instance().publish(event);

    return true;
}

bool CaseManager::updateCaseStatus(const std::string& caseId, CaseStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = cases_.find(caseId);
    if (it == cases_.end()) {
        logger_.warn("updateCaseStatus failed: case {} not found", caseId);
        return false;
    }

    CaseStatus current = it->second.status;

    if (!isValidTransition(current, status)) {
        logger_.warn("updateCaseStatus failed: invalid transition for case {}", caseId);
        return false;
    }

    it->second.status = status;
    logger_.info("Updated case {} status to {}", caseId, static_cast<int>(status));
    return true;
}

bool CaseManager::isValidTransition(CaseStatus from, CaseStatus to) const {
    // Cannot reopen a closed case
    if (from == CaseStatus::Closed) {
        return false;
    }

    // Cannot go backward from Resolved except to Closed
    if (from == CaseStatus::Resolved && to != CaseStatus::Closed) {
        return false;
    }

    return true;
}

bool CaseManager::caseExists(const std::string& caseId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cases_.find(caseId) != cases_.end();
}

CaseInfo CaseManager::getCase(const std::string& caseId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cases_.find(caseId);
    if (it != cases_.end()) {
        return it->second;
    }
    return {};
}

std::vector<CaseInfo> CaseManager::getAllCases() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CaseInfo> result;
    result.reserve(cases_.size());
    for (const auto& [id, c] : cases_) {
        result.push_back(c);
    }
    return result;
}

std::vector<CaseInfo> CaseManager::getCasesByStatus(CaseStatus status) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CaseInfo> result;
    for (const auto& [id, c] : cases_) {
        if (c.status == status) {
            result.push_back(c);
        }
    }
    return result;
}

std::vector<CaseInfo> CaseManager::getCasesByAssignee(const std::string& analystId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CaseInfo> result;
    for (const auto& [id, c] : cases_) {
        if (c.assignee == analystId) {
            result.push_back(c);
        }
    }
    return result;
}

size_t CaseManager::getCaseCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cases_.size();
}

std::vector<std::string> CaseManager::getActiveAnalysts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> analysts;
    for (const auto& [id, c] : cases_) {
        if (!c.assignee.empty() && c.status != CaseStatus::Closed) {
            if (std::find(analysts.begin(), analysts.end(), c.assignee) == analysts.end()) {
                analysts.push_back(c.assignee);
            }
        }
    }
    return analysts;
}

} // namespace ThreatOne::SOC
