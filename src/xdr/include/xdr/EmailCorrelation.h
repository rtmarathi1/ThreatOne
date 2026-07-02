#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::XDR {

// Represents an email security event
struct EmailEvent {
    std::string id;
    std::string sender;
    std::string recipient;
    std::string subject;
    std::string timestamp;
    std::string severity;
    std::string eventType;  // "phishing", "malicious_attachment", "suspicious_link", "spam", "bec"
    std::vector<std::string> attachments;
    std::vector<std::string> urls;
    std::string endpointId;  // Endpoint that received/opened the email
    bool clicked = false;
    bool attachmentOpened = false;
};

// Represents a phishing campaign detection
struct PhishingCampaign {
    std::string id;
    std::string name;
    std::vector<std::string> emailEventIds;
    std::vector<std::string> targetedUsers;
    std::string senderDomain;
    int emailCount = 0;
    double confidence = 0.0;
    std::string severity;
};

// Represents email-to-endpoint correlation
struct EmailEndpointLink {
    std::string emailEventId;
    std::string endpointEventId;
    std::string linkType;  // "attachment_executed", "link_clicked", "payload_delivered"
    std::string timestamp;
};

class EmailCorrelation {
public:
    EmailCorrelation();
    ~EmailCorrelation() = default;

    // Email event submission
    std::string submitEmailEvent(const EmailEvent& event);
    [[nodiscard]] std::vector<EmailEvent> getEmailEvents() const;

    // Phishing campaign detection
    [[nodiscard]] std::vector<PhishingCampaign> detectPhishingCampaigns() const;

    // Cross-correlation with endpoint activity
    void linkEmailToEndpoint(const EmailEndpointLink& link);
    [[nodiscard]] std::vector<EmailEndpointLink> getEndpointLinks(const std::string& emailEventId) const;

    // Analysis
    [[nodiscard]] std::vector<std::string> getSuspiciousSenders() const;
    [[nodiscard]] std::vector<std::string> getMaliciousURLs() const;

    // Stats
    [[nodiscard]] size_t getEventCount() const;
    [[nodiscard]] size_t getPhishingCount() const;

private:
    std::string generateEventId();
    std::string generateCampaignId();

    mutable std::mutex mutex_;
    std::map<std::string, EmailEvent> events_;
    std::map<std::string, std::vector<EmailEndpointLink>> endpointLinks_;
    int nextEventId_ = 1;
    int nextCampaignId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
