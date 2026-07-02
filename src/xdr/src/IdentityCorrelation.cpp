#include "xdr/IdentityCorrelation.h"

#include <algorithm>
#include <set>

namespace ThreatOne::XDR {

IdentityCorrelation::IdentityCorrelation()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("IdentityCorrelation")) {
    logger_.info("IdentityCorrelation initialized");
}

std::string IdentityCorrelation::generateEventId() {
    return "IDEVT-" + std::to_string(nextEventId_++);
}

std::string IdentityCorrelation::generateThreatId() {
    return "IDTHREAT-" + std::to_string(nextThreatId_++);
}

std::string IdentityCorrelation::generateAnomalyId() {
    return "IDANOM-" + std::to_string(nextAnomalyId_++);
}

std::string IdentityCorrelation::submitIdentityEvent(const IdentityEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string id = event.id.empty() ? generateEventId() : event.id;

    IdentityEvent stored = event;
    stored.id = id;
    events_[id] = stored;
    eventsByUser_[stored.userId].push_back(id);

    logger_.info("Submitted identity event: id={}, user={}, type={}",
                 id, event.userId, event.eventType);
    return id;
}

std::vector<IdentityEvent> IdentityCorrelation::getIdentityEvents(const std::string& userId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IdentityEvent> result;

    if (userId.empty()) {
        for (const auto& [id, evt] : events_) {
            result.push_back(evt);
        }
    } else {
        auto it = eventsByUser_.find(userId);
        if (it != eventsByUser_.end()) {
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

std::vector<IdentityThreat> IdentityCorrelation::detectIdentityThreats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IdentityThreat> threats;

    for (const auto& [userId, eventIds] : eventsByUser_) {
        // Detect brute force: multiple failed logins
        int failedLogins = 0;
        std::vector<std::string> failedIds;
        for (const auto& eid : eventIds) {
            auto evtIt = events_.find(eid);
            if (evtIt != events_.end() &&
                evtIt->second.eventType == "failed_login") {
                failedLogins++;
                failedIds.push_back(eid);
            }
        }

        if (failedLogins >= 3) {
            IdentityThreat threat;
            threat.id = "IDTHREAT-" + std::to_string(threats.size() + 1);
            threat.userId = userId;
            threat.threatType = "brute_force";
            threat.eventIds = failedIds;
            threat.description = "Brute force detected: " + std::to_string(failedLogins) + " failed logins for user " + userId;
            threat.confidence = std::min(1.0, 0.5 + (failedLogins * 0.1));
            threat.severity = failedLogins >= 5 ? "high" : "medium";
            threats.push_back(threat);
        }

        // Detect privilege escalation
        for (const auto& eid : eventIds) {
            auto evtIt = events_.find(eid);
            if (evtIt != events_.end() &&
                evtIt->second.eventType == "privilege_escalation") {
                IdentityThreat threat;
                threat.id = "IDTHREAT-" + std::to_string(threats.size() + 1);
                threat.userId = userId;
                threat.threatType = "privilege_abuse";
                threat.eventIds = {eid};
                threat.description = "Privilege escalation by user " + userId;
                threat.confidence = 0.8;
                threat.severity = "high";
                threats.push_back(threat);
            }
        }

        // Detect impossible travel: logins from different locations in short time
        std::set<std::string> geoLocations;
        for (const auto& eid : eventIds) {
            auto evtIt = events_.find(eid);
            if (evtIt != events_.end() &&
                (evtIt->second.eventType == "login") &&
                !evtIt->second.geoLocation.empty()) {
                geoLocations.insert(evtIt->second.geoLocation);
            }
        }

        if (geoLocations.size() >= 2) {
            IdentityThreat threat;
            threat.id = "IDTHREAT-" + std::to_string(threats.size() + 1);
            threat.userId = userId;
            threat.threatType = "impossible_travel";
            threat.description = "User " + userId + " logged in from " +
                                 std::to_string(geoLocations.size()) + " different locations";
            threat.confidence = 0.75;
            threat.severity = "high";
            threats.push_back(threat);
        }
    }

    return threats;
}

std::vector<AccessAnomaly> IdentityCorrelation::detectAccessAnomalies() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AccessAnomaly> anomalies;

    for (const auto& [userId, eventIds] : eventsByUser_) {
        // Detect unusual systems access (accessing many different systems)
        std::set<std::string> systems;
        for (const auto& eid : eventIds) {
            auto evtIt = events_.find(eid);
            if (evtIt != events_.end() && !evtIt->second.system.empty()) {
                systems.insert(evtIt->second.system);
            }
        }

        if (systems.size() >= 4) {
            AccessAnomaly anomaly;
            anomaly.id = "IDANOM-" + std::to_string(anomalies.size() + 1);
            anomaly.userId = userId;
            anomaly.anomalyType = "excessive_access";
            anomaly.details = "User accessed " + std::to_string(systems.size()) + " different systems";
            anomaly.riskScore = std::min(1.0, 0.3 + (systems.size() * 0.1));
            anomalies.push_back(anomaly);
        }
    }

    return anomalies;
}

bool IdentityCorrelation::isBruteForceDetected(const std::string& userId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = eventsByUser_.find(userId);
    if (it == eventsByUser_.end()) return false;

    int failedLogins = 0;
    for (const auto& eid : it->second) {
        auto evtIt = events_.find(eid);
        if (evtIt != events_.end() && evtIt->second.eventType == "failed_login") {
            failedLogins++;
        }
    }

    return failedLogins >= 3;
}

bool IdentityCorrelation::isImpossibleTravel(const std::string& userId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = eventsByUser_.find(userId);
    if (it == eventsByUser_.end()) return false;

    std::set<std::string> geoLocations;
    for (const auto& eid : it->second) {
        auto evtIt = events_.find(eid);
        if (evtIt != events_.end() &&
            evtIt->second.eventType == "login" &&
            !evtIt->second.geoLocation.empty()) {
            geoLocations.insert(evtIt->second.geoLocation);
        }
    }

    return geoLocations.size() >= 2;
}

size_t IdentityCorrelation::getEventCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_.size();
}

size_t IdentityCorrelation::getFailedLoginCount(const std::string& userId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = eventsByUser_.find(userId);
    if (it == eventsByUser_.end()) return 0;

    size_t count = 0;
    for (const auto& eid : it->second) {
        auto evtIt = events_.find(eid);
        if (evtIt != events_.end() && evtIt->second.eventType == "failed_login") {
            count++;
        }
    }
    return count;
}

std::vector<std::string> IdentityCorrelation::getActiveUsers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> users;
    users.reserve(eventsByUser_.size());
    for (const auto& [userId, ids] : eventsByUser_) {
        users.push_back(userId);
    }
    return users;
}

} // namespace ThreatOne::XDR
