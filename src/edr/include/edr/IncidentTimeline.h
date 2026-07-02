#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "core/Logger.h"
#include <cstdint>

namespace ThreatOne::EDR {

// Event in an incident timeline
struct TimelineEvent {
    std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
    std::string source;         // Module/component that generated the event
    std::string type;           // Event type (e.g., "file_access", "process_exec", "network")
    std::string description;
    std::string severity;       // "info", "low", "medium", "high", "critical"
    std::vector<std::string> relatedEntities; // PIDs, file paths, IPs
};

// An incident containing correlated events
struct Incident {
    std::string id;
    std::string name;
    std::string severity;       // Current severity (may escalate)
    std::string status;         // "active", "resolved", "investigating"
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point updatedAt;
    std::vector<TimelineEvent> events;
};

class IncidentTimeline {
public:
    IncidentTimeline();
    ~IncidentTimeline() = default;

    // Create a new incident, returns incident ID
    [[nodiscard]] std::string createIncident(const std::string& name, const std::string& severity);

    // Add an event to an existing incident
    bool addEvent(const std::string& incidentId, const TimelineEvent& event);

    // Get the timeline (ordered events) for an incident
    [[nodiscard]] std::vector<TimelineEvent> getTimeline(const std::string& incidentId) const;

    // Get all active incidents
    [[nodiscard]] std::vector<Incident> getActiveIncidents() const;

    // Get a specific incident
    [[nodiscard]] std::optional<Incident> getIncident(const std::string& incidentId) const;

    // Correlate events: find events that share attributes with the given event
    [[nodiscard]] std::vector<std::string> correlateEvents(const TimelineEvent& event) const;

    // Resolve an incident
    bool resolveIncident(const std::string& incidentId);

    // Set maximum number of resolved incidents to retain (oldest evicted when full)
    void setMaxResolvedIncidents(size_t maxResolved);

    // Clear all incidents
    void clear();

private:
    [[nodiscard]] std::string generateId();
    [[nodiscard]] int severityToInt(const std::string& severity) const;
    [[nodiscard]] std::string intToSeverity(int level) const;
    void escalateSeverity(Incident& incident, const std::string& eventSeverity);
    void pruneResolvedIncidents();
    [[nodiscard]] bool entitiesOverlap(const std::vector<std::string>& a,
                                       const std::vector<std::string>& b) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;
    std::unordered_map<std::string, Incident> incidents_;
    uint64_t nextId_ = 1;
    size_t maxResolvedIncidents_ = 1000;
};

} // namespace ThreatOne::EDR
