#include "xdr/CloudCorrelation.h"

#include <algorithm>

namespace ThreatOne::XDR {

CloudCorrelation::CloudCorrelation()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("CloudCorrelation")) {
    logger_.info("CloudCorrelation initialized");
}

std::string CloudCorrelation::generateEventId() {
    return "CLOUDEVT-" + std::to_string(nextEventId_++);
}

std::string CloudCorrelation::generateThreatId() {
    return "CLOUDTHREAT-" + std::to_string(nextThreatId_++);
}

std::string CloudCorrelation::generateCorrelationId() {
    return "CLOUDCORR-" + std::to_string(nextCorrelationId_++);
}

std::string CloudCorrelation::submitCloudEvent(const CloudEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string id = event.id.empty() ? generateEventId() : event.id;

    CloudEvent stored = event;
    stored.id = id;
    events_[id] = stored;
    eventsByProvider_[stored.provider].push_back(id);
    if (!stored.principal.empty()) {
        eventsByPrincipal_[stored.principal].push_back(id);
    }

    logger_.info("Submitted cloud event: id={}, provider={}, type={}",
                 id, event.provider, event.eventType);
    return id;
}

std::vector<CloudEvent> CloudCorrelation::getCloudEvents(const std::string& provider) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CloudEvent> result;

    if (provider.empty()) {
        for (const auto& [id, evt] : events_) {
            result.push_back(evt);
        }
    } else {
        auto it = eventsByProvider_.find(provider);
        if (it != eventsByProvider_.end()) {
            for (const auto& eid : it->second) {
                auto evtIt = events_.find(eid);
                if (evtIt != events_.end()) {
                    result.push_back(evtIt->second);
                }
            }
        }
    }

    return result;
}

std::vector<CloudThreat> CloudCorrelation::detectCloudThreats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CloudThreat> threats;

    // Detect privilege escalation by principal
    for (const auto& [principal, eventIds] : eventsByPrincipal_) {
        int iamChanges = 0;
        std::vector<std::string> iamEventIds;
        for (const auto& eid : eventIds) {
            auto evtIt = events_.find(eid);
            if (evtIt != events_.end() && evtIt->second.eventType == "iam_change") {
                iamChanges++;
                iamEventIds.push_back(eid);
            }
        }

        if (iamChanges >= 2) {
            CloudThreat threat;
            threat.id = "CLOUDTHREAT-" + std::to_string(threats.size() + 1);
            threat.provider = "";
            if (!iamEventIds.empty()) {
                auto it = events_.find(iamEventIds[0]);
                if (it != events_.end()) {
                    threat.provider = it->second.provider;
                }
            }
            threat.threatType = "privilege_escalation";
            threat.eventIds = iamEventIds;
            threat.description = "Multiple IAM changes by principal: " + principal;
            threat.confidence = std::min(1.0, 0.5 + (iamChanges * 0.15));
            threat.severity = iamChanges >= 3 ? "critical" : "high";
            threats.push_back(threat);
        }
    }

    // Detect anomalous events
    std::vector<std::string> anomalousIds;
    for (const auto& [id, evt] : events_) {
        if (evt.anomalous) {
            anomalousIds.push_back(id);
        }
    }

    if (anomalousIds.size() >= 2) {
        CloudThreat threat;
        threat.id = "CLOUDTHREAT-" + std::to_string(threats.size() + 1);
        threat.threatType = "resource_hijack";
        threat.eventIds = anomalousIds;
        threat.description = "Multiple anomalous cloud events detected";
        threat.confidence = std::min(1.0, 0.4 + (anomalousIds.size() * 0.15));
        threat.severity = "high";
        threats.push_back(threat);
    }

    return threats;
}

std::vector<CloudEvent> CloudCorrelation::getIAMChanges(const std::string& principal) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CloudEvent> result;

    for (const auto& [id, evt] : events_) {
        if (evt.eventType == "iam_change") {
            if (principal.empty() || evt.principal == principal) {
                result.push_back(evt);
            }
        }
    }

    return result;
}

bool CloudCorrelation::isPrivilegeEscalation(const std::string& eventId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = events_.find(eventId);
    if (it == events_.end()) return false;

    const auto& evt = it->second;
    // Check if event is an IAM change that grants elevated permissions
    if (evt.eventType == "iam_change" &&
        (evt.action.find("admin") != std::string::npos ||
         evt.action.find("root") != std::string::npos ||
         evt.action.find("escalat") != std::string::npos ||
         evt.action.find("attach_policy") != std::string::npos)) {
        return true;
    }

    return false;
}

std::vector<Correlation> CloudCorrelation::correlateAcrossProviders() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Correlation> correlations;

    if (eventsByProvider_.size() < 2) return correlations;

    // Group by principal across providers
    std::map<std::string, std::map<std::string, std::vector<std::string>>> principalAcrossProviders;
    for (const auto& [id, evt] : events_) {
        if (!evt.principal.empty()) {
            principalAcrossProviders[evt.principal][evt.provider].push_back(id);
        }
    }

    int corrNum = 1;
    for (const auto& [principal, providers] : principalAcrossProviders) {
        if (providers.size() >= 2) {
            Correlation corr;
            corr.id = "CLOUDCORR-" + std::to_string(corrNum++);
            corr.description = "Cross-provider activity by principal: " + principal;
            corr.confidence = std::min(1.0, 0.5 + (static_cast<double>(providers.size()) * 0.15));
            corr.severity = "medium";

            for (const auto& [prov, ids] : providers) {
                for (const auto& id : ids) {
                    corr.eventIds.push_back(id);
                }
            }

            correlations.push_back(corr);
        }
    }

    return correlations;
}

size_t CloudCorrelation::getEventCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_.size();
}

size_t CloudCorrelation::getEventCountByProvider(const std::string& provider) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = eventsByProvider_.find(provider);
    if (it != eventsByProvider_.end()) {
        return it->second.size();
    }
    return 0;
}

} // namespace ThreatOne::XDR
