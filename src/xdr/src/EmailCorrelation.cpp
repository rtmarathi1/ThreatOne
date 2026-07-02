#include "xdr/EmailCorrelation.h"

#include <algorithm>
#include <set>

namespace ThreatOne::XDR {

EmailCorrelation::EmailCorrelation()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("EmailCorrelation")) {
    logger_.info("EmailCorrelation initialized");
}

std::string EmailCorrelation::generateEventId() {
    return "EMAILEVT-" + std::to_string(nextEventId_++);
}

std::string EmailCorrelation::generateCampaignId() {
    return "CAMPAIGN-" + std::to_string(nextCampaignId_++);
}

std::string EmailCorrelation::submitEmailEvent(const EmailEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string id = event.id.empty() ? generateEventId() : event.id;

    EmailEvent stored = event;
    stored.id = id;
    events_[id] = stored;

    logger_.info("Submitted email event: id={}, sender={}, type={}",
                 id, event.sender, event.eventType);
    return id;
}

std::vector<EmailEvent> EmailCorrelation::getEmailEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<EmailEvent> result;
    result.reserve(events_.size());
    for (const auto& [id, evt] : events_) {
        result.push_back(evt);
    }
    return result;
}

std::vector<PhishingCampaign> EmailCorrelation::detectPhishingCampaigns() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PhishingCampaign> campaigns;

    // Group phishing emails by sender domain
    std::map<std::string, std::vector<const EmailEvent*>> bySenderDomain;
    for (const auto& [id, evt] : events_) {
        if (evt.eventType == "phishing" || evt.eventType == "bec") {
            // Extract domain from sender
            std::string domain;
            auto atPos = evt.sender.find('@');
            if (atPos != std::string::npos) {
                domain = evt.sender.substr(atPos + 1);
            } else {
                domain = evt.sender;
            }
            bySenderDomain[domain].push_back(&evt);
        }
    }

    // If 2+ phishing emails from same domain, it is a campaign
    int campaignNum = 1;
    for (const auto& [domain, emailPtrs] : bySenderDomain) {
        if (emailPtrs.size() >= 2) {
            PhishingCampaign campaign;
            campaign.id = "CAMPAIGN-" + std::to_string(campaignNum++);
            campaign.name = "Phishing campaign from " + domain;
            campaign.senderDomain = domain;
            campaign.emailCount = static_cast<int>(emailPtrs.size());
            campaign.confidence = std::min(1.0, 0.5 + (emailPtrs.size() * 0.1));
            campaign.severity = emailPtrs.size() >= 5 ? "critical" : "high";

            std::set<std::string> targets;
            for (const auto* email : emailPtrs) {
                campaign.emailEventIds.push_back(email->id);
                targets.insert(email->recipient);
            }
            campaign.targetedUsers = std::vector<std::string>(targets.begin(), targets.end());
            campaigns.push_back(campaign);
        }
    }

    return campaigns;
}

void EmailCorrelation::linkEmailToEndpoint(const EmailEndpointLink& link) {
    std::lock_guard<std::mutex> lock(mutex_);
    endpointLinks_[link.emailEventId].push_back(link);
    logger_.info("Linked email {} to endpoint event {}: {}",
                 link.emailEventId, link.endpointEventId, link.linkType);
}

std::vector<EmailEndpointLink> EmailCorrelation::getEndpointLinks(const std::string& emailEventId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = endpointLinks_.find(emailEventId);
    if (it != endpointLinks_.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::string> EmailCorrelation::getSuspiciousSenders() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<std::string> senders;

    for (const auto& [id, evt] : events_) {
        if (evt.eventType == "phishing" || evt.eventType == "malicious_attachment" || evt.eventType == "bec") {
            senders.insert(evt.sender);
        }
    }

    return std::vector<std::string>(senders.begin(), senders.end());
}

std::vector<std::string> EmailCorrelation::getMaliciousURLs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<std::string> urls;

    for (const auto& [id, evt] : events_) {
        if (evt.eventType == "suspicious_link" || evt.eventType == "phishing") {
            for (const auto& url : evt.urls) {
                urls.insert(url);
            }
        }
    }

    return std::vector<std::string>(urls.begin(), urls.end());
}

size_t EmailCorrelation::getEventCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_.size();
}

size_t EmailCorrelation::getPhishingCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, evt] : events_) {
        if (evt.eventType == "phishing") {
            count++;
        }
    }
    return count;
}

} // namespace ThreatOne::XDR
