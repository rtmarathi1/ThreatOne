#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>

namespace ThreatOne::XDR {

class XDREngine : public IXDREngine {
public:
    XDREngine();
    ~XDREngine() override = default;

    std::vector<Correlation> correlateEvents(const std::vector<std::string>& eventIds) override;
    [[nodiscard]] std::vector<Correlation> getCorrelations() override;
    std::string startInvestigation(const std::string& correlationId) override;
    [[nodiscard]] std::vector<TimelineEntry> getTimeline(const std::string& investigationId) override;
    [[nodiscard]] std::vector<Incident> getIncidents() override;

    // Extended methods
    std::string submitEndpointEvent(const EndpointEvent& event) override;
    std::vector<Correlation> correlateAcrossSources(const std::vector<CrossSourceAlert>& alerts) override;
    std::string startAutomatedInvestigation(const std::string& correlationId, const std::string& playbook) override;
    [[nodiscard]] Investigation getInvestigation(const std::string& investigationId) override;
    std::string executeResponseAction(const ResponseAction& action) override;
    [[nodiscard]] std::vector<ResponseAction> getResponseActions() override;
    [[nodiscard]] std::vector<Investigation> getActiveInvestigations() override;

private:
    std::string generateEventId();
    std::string generateCorrelationId();
    std::string generateInvestigationId();
    std::string generateActionId();
    std::string generateIncidentId();

    bool eventsWithinTimeWindow(const EndpointEvent& a, const EndpointEvent& b, int windowSeconds = 300) const;
    int severityToInt(const std::string& severity) const;

    mutable std::mutex mutex_;
    int nextEventId_ = 1;
    int nextCorrelationId_ = 1;
    int nextInvestigationId_ = 1;
    int nextActionId_ = 1;
    int nextIncidentId_ = 1;

    std::map<std::string, EndpointEvent> events_;
    std::map<std::string, Correlation> correlations_;
    std::map<std::string, Investigation> investigations_;
    std::map<std::string, ResponseAction> responseActions_;
    std::map<std::string, Incident> incidents_;

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
