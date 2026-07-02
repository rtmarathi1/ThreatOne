#include "soc/IncidentManager.h"
#include <mutex>

#include <algorithm>

namespace ThreatOne::SOC {

IncidentManager::IncidentManager()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("IncidentManager")) {
    logger_.info("IncidentManager initialized");
}

std::string IncidentManager::createIncident(const IncidentInfo& incident) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string id = "INC-" + std::to_string(nextIncidentId_++);
    IncidentInfo stored = incident;
    stored.id = id;
    stored.status = IncidentStatus::Open;
    incidents_[id] = stored;

    logger_.info("Created incident: id={}, title={}, severity={}",
                 id, incident.title, static_cast<int>(incident.severity));
    return id;
}

bool IncidentManager::updateIncidentStatus(const std::string& incidentId, IncidentStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = incidents_.find(incidentId);
    if (it == incidents_.end()) {
        logger_.warn("updateIncidentStatus failed: incident {} not found", incidentId);
        return false;
    }

    // Cannot reopen closed incident
    if (it->second.status == IncidentStatus::Closed) {
        logger_.warn("updateIncidentStatus failed: incident {} is closed", incidentId);
        return false;
    }

    it->second.status = status;
    logger_.info("Updated incident {} status to {}", incidentId, static_cast<int>(status));
    return true;
}

bool IncidentManager::assignLead(const std::string& incidentId, const std::string& analystId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = incidents_.find(incidentId);
    if (it == incidents_.end()) {
        logger_.warn("assignLead failed: incident {} not found", incidentId);
        return false;
    }

    it->second.leadAnalyst = analystId;
    logger_.info("Assigned lead {} to incident {}", analystId, incidentId);
    return true;
}

bool IncidentManager::addCaseToIncident(const std::string& incidentId, const std::string& caseId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = incidents_.find(incidentId);
    if (it == incidents_.end()) {
        logger_.warn("addCaseToIncident failed: incident {} not found", incidentId);
        return false;
    }

    auto& cases = it->second.caseIds;
    if (std::find(cases.begin(), cases.end(), caseId) != cases.end()) {
        return false;  // already associated
    }

    cases.push_back(caseId);
    logger_.info("Added case {} to incident {}", caseId, incidentId);
    return true;
}

bool IncidentManager::removeCaseFromIncident(const std::string& incidentId, const std::string& caseId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = incidents_.find(incidentId);
    if (it == incidents_.end()) {
        return false;
    }

    auto& cases = it->second.caseIds;
    auto caseIt = std::find(cases.begin(), cases.end(), caseId);
    if (caseIt == cases.end()) {
        return false;
    }

    cases.erase(caseIt);
    logger_.info("Removed case {} from incident {}", caseId, incidentId);
    return true;
}

bool IncidentManager::incidentExists(const std::string& incidentId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return incidents_.find(incidentId) != incidents_.end();
}

IncidentInfo IncidentManager::getIncident(const std::string& incidentId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = incidents_.find(incidentId);
    if (it != incidents_.end()) {
        return it->second;
    }
    return {};
}

std::vector<IncidentInfo> IncidentManager::getAllIncidents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IncidentInfo> result;
    result.reserve(incidents_.size());
    for (const auto& [id, inc] : incidents_) {
        result.push_back(inc);
    }
    return result;
}

std::vector<IncidentInfo> IncidentManager::getIncidentsBySeverity(IncidentSeverity severity) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IncidentInfo> result;
    for (const auto& [id, inc] : incidents_) {
        if (inc.severity == severity) {
            result.push_back(inc);
        }
    }
    return result;
}

std::vector<IncidentInfo> IncidentManager::getOpenIncidents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IncidentInfo> result;
    for (const auto& [id, inc] : incidents_) {
        if (inc.status != IncidentStatus::Closed) {
            result.push_back(inc);
        }
    }
    return result;
}

size_t IncidentManager::getIncidentCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return incidents_.size();
}

bool IncidentManager::updateSeverity(const std::string& incidentId, IncidentSeverity severity) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = incidents_.find(incidentId);
    if (it == incidents_.end()) {
        return false;
    }

    it->second.severity = severity;
    logger_.info("Updated incident {} severity to {}", incidentId, static_cast<int>(severity));
    return true;
}

} // namespace ThreatOne::SOC
