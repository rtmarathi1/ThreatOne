#pragma once

#include <string>
#include <vector>
#include <unordered_map>

namespace ThreatOne::XDR {

struct Correlation {
    std::string id;
    std::string description;
    std::vector<std::string> eventIds;
    double confidence = 0.0;
    std::string severity;
};

struct TimelineEntry {
    std::string timestamp;
    std::string eventType;
    std::string description;
    std::string source;
};

struct Incident {
    std::string id;
    std::string title;
    std::string severity;
    std::string status;
    std::vector<std::string> correlationIds;
    std::vector<TimelineEntry> timeline;
};

struct EndpointEvent {
    std::string id;
    std::string endpointId;
    std::string eventType;
    std::string timestamp;
    std::string severity;
    std::unordered_map<std::string, std::string> details;
};

enum class ActionType {
    IsolateEndpoint,
    BlockIP,
    DisableUser,
    KillProcess
};

enum class ActionStatus {
    Pending,
    InProgress,
    Completed,
    Failed
};

struct ResponseAction {
    std::string id;
    ActionType type = ActionType::IsolateEndpoint;
    std::string target;
    ActionStatus status = ActionStatus::Pending;
    std::string timestamp;
};

enum class InvestigationStatus {
    InProgress,
    Completed,
    Failed
};

struct Investigation {
    std::string id;
    std::string correlationId;
    InvestigationStatus status = InvestigationStatus::InProgress;
    std::vector<std::string> findings;
    std::vector<std::string> evidence;
    std::string playbook;
};

enum class AlertSource {
    Email,
    Cloud,
    Identity,
    Network,
    Endpoint
};

struct CrossSourceAlert {
    std::string id;
    AlertSource source = AlertSource::Endpoint;
    std::string originalAlertId;
    std::string normalizedSeverity;
    std::string description;
    std::string timestamp;
};

class IXDREngine {
public:
    virtual ~IXDREngine() = default;

    virtual std::vector<Correlation> correlateEvents(const std::vector<std::string>& eventIds) = 0;
    virtual std::vector<Correlation> getCorrelations() = 0;
    virtual std::string startInvestigation(const std::string& correlationId) = 0;
    virtual std::vector<TimelineEntry> getTimeline(const std::string& investigationId) = 0;
    virtual std::vector<Incident> getIncidents() = 0;

    // Extended methods
    virtual std::string submitEndpointEvent(const EndpointEvent& event) = 0;
    virtual std::vector<Correlation> correlateAcrossSources(const std::vector<CrossSourceAlert>& alerts) = 0;
    virtual std::string startAutomatedInvestigation(const std::string& correlationId, const std::string& playbook) = 0;
    virtual Investigation getInvestigation(const std::string& investigationId) = 0;
    virtual std::string executeResponseAction(const ResponseAction& action) = 0;
    virtual std::vector<ResponseAction> getResponseActions() = 0;
    virtual std::vector<Investigation> getActiveInvestigations() = 0;
};

} // namespace ThreatOne::XDR
