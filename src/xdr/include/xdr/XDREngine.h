#pragma once

#include "xdr/IXDREngine.h"
#include "xdr/EndpointCorrelation.h"
#include "xdr/NetworkCorrelation.h"
#include "xdr/EmailCorrelation.h"
#include "xdr/CloudCorrelation.h"
#include "xdr/IdentityCorrelation.h"
#include "xdr/AutomatedInvestigation.h"
#include "xdr/ThreatHunting.h"
#include "xdr/ResponseOrchestrator.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <memory>
#include <string>
#include <vector>

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

    // Access to sub-components for advanced usage
    [[nodiscard]] EndpointCorrelation& getEndpointCorrelation() { return *endpointCorrelation_; }
    [[nodiscard]] NetworkCorrelation& getNetworkCorrelation() { return *networkCorrelation_; }
    [[nodiscard]] EmailCorrelation& getEmailCorrelation() { return *emailCorrelation_; }
    [[nodiscard]] CloudCorrelation& getCloudCorrelation() { return *cloudCorrelation_; }
    [[nodiscard]] IdentityCorrelation& getIdentityCorrelation() { return *identityCorrelation_; }
    [[nodiscard]] AutomatedInvestigation& getAutomatedInvestigation() { return *automatedInvestigation_; }
    [[nodiscard]] ThreatHunting& getThreatHunting() { return *threatHunting_; }
    [[nodiscard]] ResponseOrchestrator& getResponseOrchestrator() { return *responseOrchestrator_; }

private:
    std::string generateCorrelationId();
    std::string generateIncidentId();

    int severityToInt(const std::string& severity) const;

    // Sub-components
    std::shared_ptr<EndpointCorrelation> endpointCorrelation_;
    std::shared_ptr<NetworkCorrelation> networkCorrelation_;
    std::shared_ptr<EmailCorrelation> emailCorrelation_;
    std::shared_ptr<CloudCorrelation> cloudCorrelation_;
    std::shared_ptr<IdentityCorrelation> identityCorrelation_;
    std::shared_ptr<AutomatedInvestigation> automatedInvestigation_;
    std::shared_ptr<ThreatHunting> threatHunting_;
    std::shared_ptr<ResponseOrchestrator> responseOrchestrator_;

    // Orchestrator-level state
    mutable std::mutex mutex_;
    int nextCorrelationId_ = 1;
    int nextIncidentId_ = 1;

    std::map<std::string, Correlation> correlations_;
    std::map<std::string, Incident> incidents_;

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
