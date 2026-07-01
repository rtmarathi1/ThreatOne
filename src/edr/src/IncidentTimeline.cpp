#include "edr/IncidentTimeline.h"

#include <algorithm>
#include <optional>

namespace ThreatOne::EDR {

IncidentTimeline::IncidentTimeline()
    : logger_(Core::Logger::instance().getModuleLogger("IncidentTimeline"))
{
    logger_.info("IncidentTimeline initialized");
}

std::string IncidentTimeline::createIncident(const std::string& name, const std::string& severity) {
    std::lock_guard lock(mutex_);

    std::string id = generateId();

    Incident incident;
    incident.id = id;
    incident.name = name;
    incident.severity = severity;
    incident.status = "active";
    incident.createdAt = std::chrono::steady_clock::now();
    incident.updatedAt = incident.createdAt;

    incidents_[id] = incident;
    logger_.info("Incident created: {} ({})", name, id);

    return id;
}

bool IncidentTimeline::addEvent(const std::string& incidentId, const TimelineEvent& event) {
    std::lock_guard lock(mutex_);

    auto it = incidents_.find(incidentId);
    if (it == incidents_.end()) {
        logger_.error("Incident not found: {}", incidentId);
        return false;
    }

    it->second.events.push_back(event);
    it->second.updatedAt = std::chrono::steady_clock::now();

    // Auto-escalate severity if new event is high severity
    escalateSeverity(it->second, event.severity);

    logger_.debug("Event added to incident {}: {}", incidentId, event.description);
    return true;
}

std::vector<TimelineEvent> IncidentTimeline::getTimeline(const std::string& incidentId) const {
    std::lock_guard lock(mutex_);

    auto it = incidents_.find(incidentId);
    if (it == incidents_.end()) {
        return {};
    }

    // Return events sorted chronologically
    std::vector<TimelineEvent> timeline = it->second.events;
    std::sort(timeline.begin(), timeline.end(),
              [](const TimelineEvent& a, const TimelineEvent& b) {
                  return a.timestamp < b.timestamp;
              });

    return timeline;
}

std::vector<Incident> IncidentTimeline::getActiveIncidents() const {
    std::lock_guard lock(mutex_);
    std::vector<Incident> active;

    for (const auto& [id, incident] : incidents_) {
        if (incident.status == "active") {
            active.push_back(incident);
        }
    }

    // Sort by severity (highest first)
    std::sort(active.begin(), active.end(),
              [this](const Incident& a, const Incident& b) {
                  return severityToInt(a.severity) > severityToInt(b.severity);
              });

    return active;
}

std::optional<Incident> IncidentTimeline::getIncident(const std::string& incidentId) const {
    std::lock_guard lock(mutex_);

    auto it = incidents_.find(incidentId);
    if (it == incidents_.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::vector<std::string> IncidentTimeline::correlateEvents(const TimelineEvent& event) const {
    std::lock_guard lock(mutex_);
    std::vector<std::string> correlatedIncidents;

    for (const auto& [id, incident] : incidents_) {
        for (const auto& existingEvent : incident.events) {
            if (entitiesOverlap(event.relatedEntities, existingEvent.relatedEntities)) {
                correlatedIncidents.push_back(id);
                break;
            }
        }
    }

    return correlatedIncidents;
}

bool IncidentTimeline::resolveIncident(const std::string& incidentId) {
    std::lock_guard lock(mutex_);

    auto it = incidents_.find(incidentId);
    if (it == incidents_.end()) {
        return false;
    }

    it->second.status = "resolved";
    it->second.updatedAt = std::chrono::steady_clock::now();
    logger_.info("Incident resolved: {}", incidentId);
    return true;
}

void IncidentTimeline::clear() {
    std::lock_guard lock(mutex_);
    incidents_.clear();
    nextId_ = 1;
}

std::string IncidentTimeline::generateId() {
    return "INC-" + std::to_string(nextId_++);
}

int IncidentTimeline::severityToInt(const std::string& severity) const {
    if (severity == "critical") return 5;
    if (severity == "high") return 4;
    if (severity == "medium") return 3;
    if (severity == "low") return 2;
    if (severity == "info") return 1;
    return 0;
}

std::string IncidentTimeline::intToSeverity(int level) const {
    switch (level) {
        case 5: return "critical";
        case 4: return "high";
        case 3: return "medium";
        case 2: return "low";
        default: return "info";
    }
}

void IncidentTimeline::escalateSeverity(Incident& incident, const std::string& eventSeverity) {
    int currentLevel = severityToInt(incident.severity);
    int eventLevel = severityToInt(eventSeverity);

    if (eventLevel > currentLevel) {
        std::string oldSeverity = incident.severity;
        incident.severity = intToSeverity(eventLevel);
        logger_.warn("Incident {} escalated from {} to {}", 
                     incident.id, oldSeverity, incident.severity);
    }
}

bool IncidentTimeline::entitiesOverlap(const std::vector<std::string>& a,
                                        const std::vector<std::string>& b) const {
    for (const auto& entityA : a) {
        for (const auto& entityB : b) {
            if (entityA == entityB) return true;
            // Also check for prefix matching (same file path prefix, same PID)
            if (!entityA.empty() && !entityB.empty()) {
                // Check if one is a prefix of the other (for file paths)
                if (entityA.front() == '/' && entityB.front() == '/') {
                    if (entityA.rfind(entityB, 0) == 0 || entityB.rfind(entityA, 0) == 0) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

} // namespace ThreatOne::EDR
