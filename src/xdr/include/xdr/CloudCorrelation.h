#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::XDR {

// Represents a cloud event
struct CloudEvent {
    std::string id;
    std::string provider;  // "aws", "azure", "gcp"
    std::string service;   // "s3", "iam", "ec2", "compute", "storage"
    std::string eventType; // "api_call", "resource_modified", "iam_change", "config_change"
    std::string principal; // Who performed the action
    std::string resource;  // What was affected
    std::string action;    // Specific action taken
    std::string region;
    std::string timestamp;
    std::string severity;
    std::string sourceIP;
    bool anomalous = false;
};

// Represents detected suspicious cloud activity
struct CloudThreat {
    std::string id;
    std::string provider;
    std::string threatType;  // "privilege_escalation", "resource_hijack", "data_exposure", "crypto_mining"
    std::vector<std::string> eventIds;
    std::string description;
    double confidence = 0.0;
    std::string severity;
};

class CloudCorrelation {
public:
    CloudCorrelation();
    ~CloudCorrelation() = default;

    // Cloud event submission
    std::string submitCloudEvent(const CloudEvent& event);
    [[nodiscard]] std::vector<CloudEvent> getCloudEvents(const std::string& provider = "") const;

    // Threat detection
    [[nodiscard]] std::vector<CloudThreat> detectCloudThreats() const;

    // IAM analysis
    [[nodiscard]] std::vector<CloudEvent> getIAMChanges(const std::string& principal = "") const;
    [[nodiscard]] bool isPrivilegeEscalation(const std::string& eventId) const;

    // Cross-provider correlation
    [[nodiscard]] std::vector<Correlation> correlateAcrossProviders() const;

    // Stats
    [[nodiscard]] size_t getEventCount() const;
    [[nodiscard]] size_t getEventCountByProvider(const std::string& provider) const;

private:
    std::string generateEventId();
    std::string generateThreatId();
    std::string generateCorrelationId();

    mutable std::mutex mutex_;
    std::map<std::string, CloudEvent> events_;
    std::map<std::string, std::vector<std::string>> eventsByProvider_;
    std::map<std::string, std::vector<std::string>> eventsByPrincipal_;
    int nextEventId_ = 1;
    int nextThreatId_ = 1;
    int nextCorrelationId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
