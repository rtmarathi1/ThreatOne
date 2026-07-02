#include "xdr/XDREngine.h"

#include <algorithm>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace ThreatOne::XDR {

XDREngine::XDREngine()
    : endpointCorrelation_(std::make_shared<EndpointCorrelation>()),
      networkCorrelation_(std::make_shared<NetworkCorrelation>()),
      emailCorrelation_(std::make_shared<EmailCorrelation>()),
      cloudCorrelation_(std::make_shared<CloudCorrelation>()),
      identityCorrelation_(std::make_shared<IdentityCorrelation>()),
      automatedInvestigation_(std::make_shared<AutomatedInvestigation>()),
      threatHunting_(std::make_shared<ThreatHunting>()),
      responseOrchestrator_(std::make_shared<ResponseOrchestrator>()),
      logger_(ThreatOne::Core::Logger::instance().getModuleLogger("XDREngine")) {
    logger_.info("XDREngine initialized with sub-components");
}

std::string XDREngine::generateCorrelationId() {
    return "CORR-" + std::to_string(nextCorrelationId_++);
}

std::string XDREngine::generateIncidentId() {
    return "INC-" + std::to_string(nextIncidentId_++);
}

int XDREngine::severityToInt(const std::string& severity) const {
    if (severity == "critical") return 4;
    if (severity == "high") return 3;
    if (severity == "medium") return 2;
    if (severity == "low") return 1;
    return 0;
}

std::string XDREngine::submitEndpointEvent(const EndpointEvent& event) {
    // Delegate to EndpointCorrelation
    return endpointCorrelation_->submitEvent(event);
}

std::vector<Correlation> XDREngine::correlateEvents(const std::vector<std::string>& eventIds) {
    if (eventIds.empty()) {
        return {};
    }

    // Delegate correlation logic to EndpointCorrelation
    auto newCorrelations = endpointCorrelation_->correlateByEndpoint(eventIds);

    // Store correlations in the orchestrator-level map for later lookup
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& corr : newCorrelations) {
        // Assign orchestrator-level IDs to maintain backward compatibility
        corr.id = generateCorrelationId();
        correlations_[corr.id] = corr;
    }

    return newCorrelations;
}

std::vector<Correlation> XDREngine::correlateAcrossSources(const std::vector<CrossSourceAlert>& alerts) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (alerts.size() < 2) {
        return {};
    }

    // Group alerts by source
    std::map<AlertSource, std::vector<CrossSourceAlert>> alertsBySource;
    for (const auto& alert : alerts) {
        alertsBySource[alert.source].push_back(alert);
    }

    std::vector<Correlation> newCorrelations;

    // If alerts come from multiple sources, create a unified correlation
    if (alertsBySource.size() >= 2) {
        Correlation corr;
        corr.id = generateCorrelationId();

        std::vector<std::string> alertIds;
        int maxSeverity = 0;
        std::string sourceList;

        for (const auto& [source, sourceAlerts] : alertsBySource) {
            for (const auto& alert : sourceAlerts) {
                alertIds.push_back(alert.id.empty() ? alert.originalAlertId : alert.id);
                int sev = severityToInt(alert.normalizedSeverity);
                if (sev > maxSeverity) {
                    maxSeverity = sev;
                }
            }

            switch (source) {
                case AlertSource::Email: sourceList += "Email,"; break;
                case AlertSource::Cloud: sourceList += "Cloud,"; break;
                case AlertSource::Identity: sourceList += "Identity,"; break;
                case AlertSource::Network: sourceList += "Network,"; break;
                case AlertSource::Endpoint: sourceList += "Endpoint,"; break;
            }
        }

        if (!sourceList.empty()) {
            sourceList.pop_back();
        }

        corr.eventIds = alertIds;
        corr.description = "Cross-source correlation from: " + sourceList;
        corr.confidence = std::min(1.0, 0.4 + (alertsBySource.size() * 0.2));

        switch (maxSeverity) {
            case 4: corr.severity = "critical"; break;
            case 3: corr.severity = "high"; break;
            case 2: corr.severity = "medium"; break;
            default: corr.severity = "low"; break;
        }

        correlations_[corr.id] = corr;
        newCorrelations.push_back(corr);

        // Create an incident from this cross-source correlation
        Incident incident;
        incident.id = generateIncidentId();
        incident.title = "Cross-source incident: " + sourceList;
        incident.severity = corr.severity;
        incident.status = "open";
        incident.correlationIds.push_back(corr.id);

        TimelineEntry entry;
        entry.timestamp = alerts.front().timestamp;
        entry.eventType = "correlation_created";
        entry.description = corr.description;
        entry.source = "XDREngine";
        incident.timeline.push_back(entry);

        incidents_[incident.id] = incident;

        logger_.info("Created cross-source correlation: id={}, sources={}, confidence={}",
                     corr.id, sourceList, corr.confidence);
    }

    return newCorrelations;
}

std::vector<Correlation> XDREngine::getCorrelations() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Correlation> result;
    result.reserve(correlations_.size());
    for (const auto& [id, corr] : correlations_) {
        result.push_back(corr);
    }
    return result;
}

std::string XDREngine::startInvestigation(const std::string& correlationId) {
    return startAutomatedInvestigation(correlationId, "default");
}

std::string XDREngine::startAutomatedInvestigation(const std::string& correlationId, const std::string& playbook) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Look up correlation
    Correlation correlation;
    auto corrIt = correlations_.find(correlationId);
    if (corrIt != correlations_.end()) {
        correlation = corrIt->second;
    }

    // Gather events from EndpointCorrelation for context
    std::map<std::string, EndpointEvent> eventMap;
    for (const auto& eventId : correlation.eventIds) {
        auto evt = endpointCorrelation_->getEvent(eventId);
        if (!evt.id.empty()) {
            eventMap[eventId] = evt;
        }
    }

    // Delegate to AutomatedInvestigation
    return automatedInvestigation_->startInvestigation(correlationId, playbook, correlation, eventMap);
}

Investigation XDREngine::getInvestigation(const std::string& investigationId) {
    // Get from AutomatedInvestigation and convert to IXDREngine::Investigation
    auto result = automatedInvestigation_->getInvestigationResult(investigationId);

    Investigation inv;
    inv.id = result.investigationId;
    inv.correlationId = result.correlationId;
    inv.status = result.status;
    inv.findings = result.findings;
    inv.evidence = result.evidence;
    inv.playbook = result.playbook;
    return inv;
}

std::vector<Investigation> XDREngine::getActiveInvestigations() {
    auto activeResults = automatedInvestigation_->getActiveInvestigations();

    std::vector<Investigation> result;
    result.reserve(activeResults.size());
    for (const auto& ar : activeResults) {
        Investigation inv;
        inv.id = ar.investigationId;
        inv.correlationId = ar.correlationId;
        inv.status = ar.status;
        inv.findings = ar.findings;
        inv.evidence = ar.evidence;
        inv.playbook = ar.playbook;
        result.push_back(inv);
    }
    return result;
}

std::string XDREngine::executeResponseAction(const ResponseAction& action) {
    // Delegate to ResponseOrchestrator
    return responseOrchestrator_->executeAction(action);
}

std::vector<ResponseAction> XDREngine::getResponseActions() {
    return responseOrchestrator_->getExecutedActions();
}

std::vector<TimelineEntry> XDREngine::getTimeline(const std::string& investigationId) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Get investigation's correlation ID
    auto invResult = automatedInvestigation_->getInvestigationResult(investigationId);
    if (invResult.investigationId.empty()) {
        return {};
    }

    // Find incident with matching correlation
    for (const auto& [incId, incident] : incidents_) {
        for (const auto& corrId : incident.correlationIds) {
            if (corrId == invResult.correlationId) {
                return incident.timeline;
            }
        }
    }

    return {};
}

std::vector<Incident> XDREngine::getIncidents() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Incident> result;
    result.reserve(incidents_.size());
    for (const auto& [id, incident] : incidents_) {
        result.push_back(incident);
    }
    return result;
}

} // namespace ThreatOne::XDR
