#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::XDR {

// Represents an identity/authentication event
struct IdentityEvent {
    std::string id;
    std::string userId;
    std::string eventType;  // "login", "logout", "failed_login", "privilege_escalation", "mfa_bypass", "password_change"
    std::string sourceIP;
    std::string system;     // System where the event occurred
    std::string timestamp;
    std::string severity;
    bool successful = true;
    std::string geoLocation;
    std::string userAgent;
};

// Represents an identity-based threat
struct IdentityThreat {
    std::string id;
    std::string userId;
    std::string threatType;  // "brute_force", "credential_stuffing", "impossible_travel", "privilege_abuse", "account_takeover"
    std::vector<std::string> eventIds;
    std::string description;
    double confidence = 0.0;
    std::string severity;
};

// Represents unusual access pattern
struct AccessAnomaly {
    std::string id;
    std::string userId;
    std::string anomalyType;  // "unusual_time", "unusual_location", "unusual_system", "excessive_access"
    std::string details;
    double riskScore = 0.0;
};

class IdentityCorrelation {
public:
    IdentityCorrelation();
    ~IdentityCorrelation() = default;

    // Identity event submission
    std::string submitIdentityEvent(const IdentityEvent& event);
    [[nodiscard]] std::vector<IdentityEvent> getIdentityEvents(const std::string& userId = "") const;

    // Threat detection
    [[nodiscard]] std::vector<IdentityThreat> detectIdentityThreats() const;

    // Access anomaly detection
    [[nodiscard]] std::vector<AccessAnomaly> detectAccessAnomalies() const;

    // Brute force detection
    [[nodiscard]] bool isBruteForceDetected(const std::string& userId) const;

    // Impossible travel detection
    [[nodiscard]] bool isImpossibleTravel(const std::string& userId) const;

    // Stats
    [[nodiscard]] size_t getEventCount() const;
    [[nodiscard]] size_t getFailedLoginCount(const std::string& userId) const;
    [[nodiscard]] std::vector<std::string> getActiveUsers() const;

private:
    std::string generateEventId();
    std::string generateThreatId();
    std::string generateAnomalyId();

    mutable std::mutex mutex_;
    std::map<std::string, IdentityEvent> events_;
    std::map<std::string, std::vector<std::string>> eventsByUser_;
    int nextEventId_ = 1;
    int nextThreatId_ = 1;
    int nextAnomalyId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
