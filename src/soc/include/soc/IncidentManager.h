#pragma once

#include "soc/ISOCManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <chrono>

namespace ThreatOne::SOC {

enum class IncidentSeverity {
    Low,
    Medium,
    High,
    Critical
};

enum class IncidentStatus {
    Open,
    Investigating,
    Contained,
    Eradicated,
    Recovered,
    Closed
};

struct IncidentInfo {
    std::string id;
    std::string title;
    std::string description;
    IncidentSeverity severity = IncidentSeverity::Medium;
    IncidentStatus status = IncidentStatus::Open;
    std::vector<std::string> caseIds;
    std::string leadAnalyst;
    std::string createdAt;
    std::string updatedAt;
    std::vector<std::string> tags;
};

class IncidentManager {
public:
    IncidentManager();
    ~IncidentManager() = default;

    // Incident lifecycle
    std::string createIncident(const IncidentInfo& incident);
    bool updateIncidentStatus(const std::string& incidentId, IncidentStatus status);
    bool assignLead(const std::string& incidentId, const std::string& analystId);

    // Case association
    bool addCaseToIncident(const std::string& incidentId, const std::string& caseId);
    bool removeCaseFromIncident(const std::string& incidentId, const std::string& caseId);

    // Queries
    [[nodiscard]] bool incidentExists(const std::string& incidentId) const;
    [[nodiscard]] IncidentInfo getIncident(const std::string& incidentId) const;
    [[nodiscard]] std::vector<IncidentInfo> getAllIncidents() const;
    [[nodiscard]] std::vector<IncidentInfo> getIncidentsBySeverity(IncidentSeverity severity) const;
    [[nodiscard]] std::vector<IncidentInfo> getOpenIncidents() const;
    [[nodiscard]] size_t getIncidentCount() const;

    // Severity management
    bool updateSeverity(const std::string& incidentId, IncidentSeverity severity);

private:
    mutable std::mutex mutex_;
    std::map<std::string, IncidentInfo> incidents_;
    int nextIncidentId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::SOC
