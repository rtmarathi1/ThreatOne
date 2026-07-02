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
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("XDREngine")) {
    logger_.info("XDREngine initialized");
}

std::string XDREngine::generateEventId() {
    return "EVT-" + std::to_string(nextEventId_++);
}

std::string XDREngine::generateCorrelationId() {
    return "CORR-" + std::to_string(nextCorrelationId_++);
}

std::string XDREngine::generateInvestigationId() {
    return "INV-" + std::to_string(nextInvestigationId_++);
}

std::string XDREngine::generateActionId() {
    return "ACT-" + std::to_string(nextActionId_++);
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

bool XDREngine::eventsWithinTimeWindow(const EndpointEvent& a, const EndpointEvent& b, int windowSeconds) const {
    // Parse ISO timestamps and compare
    if (a.timestamp.empty() || b.timestamp.empty()) {
        return true; // If no timestamp, assume within window
    }

    // Parse timestamps: expected format "YYYY-MM-DDTHH:MM:SS"
    // Use timegm/_mkgmtime for thread-safe UTC conversion
    auto parseTimestamp = [](const std::string& ts) -> std::time_t {
        std::tm tm = {};
        std::istringstream ss(ts);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (ss.fail()) {
            return 0;
        }
#ifdef _WIN32
        return _mkgmtime(&tm);
#else
        return timegm(&tm);
#endif
    };

    std::time_t timeA = parseTimestamp(a.timestamp);
    std::time_t timeB = parseTimestamp(b.timestamp);

    if (timeA == 0 || timeB == 0) {
        return true; // Unable to parse, assume within window
    }

    double diff = std::difftime(timeA, timeB);
    return std::abs(diff) <= static_cast<double>(windowSeconds);
}

std::string XDREngine::submitEndpointEvent(const EndpointEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string id = event.id.empty() ? generateEventId() : event.id;

    EndpointEvent stored = event;
    stored.id = id;
    events_[id] = stored;

    logger_.info("Submitted endpoint event: id={}, endpoint={}, type={}",
                 id, event.endpointId, event.eventType);
    return id;
}

std::vector<Correlation> XDREngine::correlateEvents(const std::vector<std::string>& eventIds) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (eventIds.empty()) {
        return {};
    }

    // Gather events by endpoint
    std::map<std::string, std::vector<EndpointEvent>> eventsByEndpoint;
    for (const auto& eventId : eventIds) {
        auto it = events_.find(eventId);
        if (it != events_.end()) {
            eventsByEndpoint[it->second.endpointId].push_back(it->second);
        }
    }

    std::vector<Correlation> newCorrelations;

    // For each endpoint with multiple events, check time window correlation
    for (auto& [endpointId, endpointEvents] : eventsByEndpoint) {
        if (endpointEvents.size() < 2) {
            continue;
        }

        // Sort by timestamp
        std::sort(endpointEvents.begin(), endpointEvents.end(),
                  [](const EndpointEvent& a, const EndpointEvent& b) {
                      return a.timestamp < b.timestamp;
                  });

        // Group events within 5-minute windows
        std::vector<std::string> windowEventIds;
        int maxSeverity = 0;

        for (size_t i = 0; i < endpointEvents.size(); ++i) {
            if (windowEventIds.empty()) {
                windowEventIds.push_back(endpointEvents[i].id);
                maxSeverity = severityToInt(endpointEvents[i].severity);
            } else {
                // Check if within window of first event in group
                if (eventsWithinTimeWindow(endpointEvents[0], endpointEvents[i], 300)) {
                    windowEventIds.push_back(endpointEvents[i].id);
                    int sev = severityToInt(endpointEvents[i].severity);
                    if (sev > maxSeverity) {
                        maxSeverity = sev;
                    }
                }
            }
        }

        if (windowEventIds.size() >= 2) {
            Correlation corr;
            corr.id = generateCorrelationId();
            corr.eventIds = windowEventIds;
            corr.description = "Multi-event correlation on endpoint " + endpointId;

            // Confidence based on number of events and severity escalation
            corr.confidence = std::min(1.0, 0.3 + (windowEventIds.size() * 0.15));

            // Detect escalating severity (multi-stage attack indicator)
            bool escalating = false;
            int prevSev = 0;
            for (const auto& evt : endpointEvents) {
                int sev = severityToInt(evt.severity);
                if (sev > prevSev && prevSev > 0) {
                    escalating = true;
                }
                prevSev = sev;
            }

            if (escalating) {
                corr.confidence = std::min(1.0, corr.confidence + 0.2);
                corr.description = "Multi-stage attack detected on endpoint " + endpointId;
            }

            // Set severity based on max
            switch (maxSeverity) {
                case 4: corr.severity = "critical"; break;
                case 3: corr.severity = "high"; break;
                case 2: corr.severity = "medium"; break;
                default: corr.severity = "low"; break;
            }

            correlations_[corr.id] = corr;
            newCorrelations.push_back(corr);

            logger_.info("Created correlation: id={}, events={}, confidence={}",
                         corr.id, windowEventIds.size(), corr.confidence);
        }
    }

    return newCorrelations;
}

std::vector<Correlation> XDREngine::correlateAcrossSources(const std::vector<CrossSourceAlert>& alerts) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (alerts.size() < 2) {
        return {};
    }

    // Group alerts by time proximity and merge from different sources
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
            sourceList.pop_back(); // Remove trailing comma
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

    Investigation inv;
    inv.id = generateInvestigationId();
    inv.correlationId = correlationId;
    inv.status = InvestigationStatus::InProgress;
    inv.playbook = playbook;

    // Look up correlation to generate findings
    auto corrIt = correlations_.find(correlationId);
    if (corrIt != correlations_.end()) {
        const auto& corr = corrIt->second;

        inv.findings.push_back("Correlation involves " + std::to_string(corr.eventIds.size()) + " events");
        inv.findings.push_back("Severity: " + corr.severity);
        inv.findings.push_back("Confidence: " + std::to_string(corr.confidence));

        if (corr.confidence >= 0.7) {
            inv.findings.push_back("High confidence - automated response recommended");
        }

        // Collect evidence from correlated events
        for (const auto& eventId : corr.eventIds) {
            auto evtIt = events_.find(eventId);
            if (evtIt != events_.end()) {
                inv.evidence.push_back("Event " + eventId + " on endpoint " +
                                       evtIt->second.endpointId + ": " +
                                       evtIt->second.eventType);
            } else {
                inv.evidence.push_back("Alert reference: " + eventId);
            }
        }
    } else {
        inv.findings.push_back("Correlation " + correlationId + " not found in store");
    }

    investigations_[inv.id] = inv;
    logger_.info("Started investigation: id={}, correlation={}, playbook={}",
                 inv.id, correlationId, playbook);
    return inv.id;
}

Investigation XDREngine::getInvestigation(const std::string& investigationId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(investigationId);
    if (it != investigations_.end()) {
        return it->second;
    }
    return Investigation{};
}

std::vector<Investigation> XDREngine::getActiveInvestigations() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Investigation> result;
    for (const auto& [id, inv] : investigations_) {
        if (inv.status == InvestigationStatus::InProgress) {
            result.push_back(inv);
        }
    }
    return result;
}

std::string XDREngine::executeResponseAction(const ResponseAction& action) {
    std::lock_guard<std::mutex> lock(mutex_);

    ResponseAction stored = action;
    stored.id = action.id.empty() ? generateActionId() : action.id;
    stored.status = ActionStatus::Completed;

    // Validate target
    if (stored.target.empty()) {
        stored.status = ActionStatus::Failed;
        logger_.warn("Response action failed: empty target");
    } else {
        logger_.info("Executed response action: id={}, type={}, target={}",
                     stored.id, static_cast<int>(stored.type), stored.target);
    }

    responseActions_[stored.id] = stored;
    return stored.id;
}

std::vector<ResponseAction> XDREngine::getResponseActions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ResponseAction> result;
    result.reserve(responseActions_.size());
    for (const auto& [id, action] : responseActions_) {
        result.push_back(action);
    }
    return result;
}

std::vector<TimelineEntry> XDREngine::getTimeline(const std::string& investigationId) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if there's an incident with this investigation's correlation
    auto invIt = investigations_.find(investigationId);
    if (invIt != investigations_.end()) {
        for (const auto& [incId, incident] : incidents_) {
            for (const auto& corrId : incident.correlationIds) {
                if (corrId == invIt->second.correlationId) {
                    return incident.timeline;
                }
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
