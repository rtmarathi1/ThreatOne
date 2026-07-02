#include "xdr/NetworkCorrelation.h"

#include <algorithm>

namespace ThreatOne::XDR {

NetworkCorrelation::NetworkCorrelation()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("NetworkCorrelation")) {
    logger_.info("NetworkCorrelation initialized");
}

std::string NetworkCorrelation::generateEventId() {
    return "NETEVT-" + std::to_string(nextEventId_++);
}

std::string NetworkCorrelation::generateDetectionId() {
    return "NETDET-" + std::to_string(nextDetectionId_++);
}

bool NetworkCorrelation::isInternalIP(const std::string& ip) const {
    // Check for RFC 1918 addresses
    return ip.find("10.") == 0 ||
           ip.find("172.16.") == 0 || ip.find("172.17.") == 0 ||
           ip.find("172.18.") == 0 || ip.find("172.19.") == 0 ||
           ip.find("172.20.") == 0 || ip.find("172.21.") == 0 ||
           ip.find("172.22.") == 0 || ip.find("172.23.") == 0 ||
           ip.find("172.24.") == 0 || ip.find("172.25.") == 0 ||
           ip.find("172.26.") == 0 || ip.find("172.27.") == 0 ||
           ip.find("172.28.") == 0 || ip.find("172.29.") == 0 ||
           ip.find("172.30.") == 0 || ip.find("172.31.") == 0 ||
           ip.find("192.168.") == 0 ||
           ip == "127.0.0.1";
}

bool NetworkCorrelation::isDGADomain(const std::string& domain) const {
    if (domain.empty()) return false;

    // Simple DGA heuristics: high consonant ratio, long random-looking names
    int consonants = 0;
    int vowels = 0;
    int digits = 0;

    // Examine only the first label (before first dot)
    std::string label = domain;
    auto dotPos = domain.find('.');
    if (dotPos != std::string::npos) {
        label = domain.substr(0, dotPos);
    }

    for (char c : label) {
        char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lower == 'a' || lower == 'e' || lower == 'i' || lower == 'o' || lower == 'u') {
            vowels++;
        } else if (std::isalpha(static_cast<unsigned char>(lower))) {
            consonants++;
        } else if (std::isdigit(static_cast<unsigned char>(c))) {
            digits++;
        }
    }

    int total = consonants + vowels + digits;
    if (total == 0) return false;

    // High consonant-to-vowel ratio is suspicious
    double consonantRatio = static_cast<double>(consonants) / total;
    if (label.length() > 10 && consonantRatio > 0.7) {
        return true;
    }

    // Mix of digits and letters in long labels is suspicious
    if (label.length() > 12 && digits > 3 && consonants > 3) {
        return true;
    }

    return false;
}

std::string NetworkCorrelation::submitNetworkEvent(const NetworkEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string id = event.id.empty() ? generateEventId() : event.id;

    NetworkEvent stored = event;
    stored.id = id;
    events_[id] = stored;

    if (!stored.endpointId.empty()) {
        eventsByEndpoint_[stored.endpointId].push_back(id);
    }
    if (!stored.destIP.empty()) {
        connectionsByDest_[stored.destIP].push_back(id);
    }

    logger_.info("Submitted network event: id={}, src={}, dst={}:{}",
                 id, event.sourceIP, event.destIP, event.destPort);
    return id;
}

std::vector<NetworkEvent> NetworkCorrelation::getNetworkEvents(const std::string& endpointId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NetworkEvent> result;

    if (endpointId.empty()) {
        for (const auto& [id, evt] : events_) {
            result.push_back(evt);
        }
    } else {
        auto it = eventsByEndpoint_.find(endpointId);
        if (it != eventsByEndpoint_.end()) {
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

std::vector<LateralMovement> NetworkCorrelation::detectLateralMovement() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LateralMovement> detections;

    // Group internal-to-internal connections by source
    std::map<std::string, std::set<std::string>> internalConnections;
    for (const auto& [id, evt] : events_) {
        if (isInternalIP(evt.sourceIP) && isInternalIP(evt.destIP) && evt.sourceIP != evt.destIP) {
            internalConnections[evt.sourceIP].insert(evt.destIP);
        }
    }

    // Flag endpoints connecting to many internal hosts
    for (const auto& [source, destinations] : internalConnections) {
        if (destinations.size() >= 3) {
            LateralMovement lm;
            lm.id = "LM-" + std::to_string(detections.size() + 1);
            lm.sourceEndpoint = source;
            lm.targetEndpoints = std::vector<std::string>(destinations.begin(), destinations.end());
            lm.technique = "network_scan_and_connect";
            lm.confidence = std::min(1.0, 0.4 + (destinations.size() * 0.1));
            detections.push_back(lm);
        }
    }

    return detections;
}

std::vector<C2Detection> NetworkCorrelation::detectC2Communication() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<C2Detection> detections;

    // Look for regular beacon-like patterns: same endpoint to same external dest
    std::map<std::string, std::vector<const NetworkEvent*>> externalComms;
    for (const auto& [id, evt] : events_) {
        if (!isInternalIP(evt.destIP) && !evt.endpointId.empty()) {
            std::string key = evt.endpointId + "->" + evt.destIP;
            externalComms[key].push_back(&evt);
        }
    }

    for (const auto& [key, evts] : externalComms) {
        if (evts.size() >= 3) {
            // Multiple connections to same external host
            C2Detection detection;
            detection.id = "C2-" + std::to_string(detections.size() + 1);
            detection.endpointId = evts[0]->endpointId;
            detection.destIP = evts[0]->destIP;
            detection.destPort = evts[0]->destPort;
            detection.beaconInterval = "regular";
            detection.confidence = std::min(1.0, 0.3 + (evts.size() * 0.15));
            detection.indicators.push_back("repeated_external_connection");
            detection.indicators.push_back("connection_count:" + std::to_string(evts.size()));
            detections.push_back(detection);
        }
    }

    return detections;
}

std::vector<ExfiltrationDetection> NetworkCorrelation::detectExfiltration() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ExfiltrationDetection> detections;

    // Look for large outbound data transfers to external IPs
    std::map<std::string, size_t> outboundByEndpoint;
    std::map<std::string, std::string> destByEndpoint;

    for (const auto& [id, evt] : events_) {
        if (!isInternalIP(evt.destIP) && evt.direction == "outbound" && evt.bytesTransferred > 0) {
            outboundByEndpoint[evt.endpointId] += evt.bytesTransferred;
            destByEndpoint[evt.endpointId] = evt.destIP;
        }
    }

    for (const auto& [endpoint, totalBytes] : outboundByEndpoint) {
        // Flag if more than 100MB transferred outbound
        if (totalBytes > 100 * 1024 * 1024) {
            ExfiltrationDetection detection;
            detection.id = "EXFIL-" + std::to_string(detections.size() + 1);
            detection.endpointId = endpoint;
            detection.destIP = destByEndpoint[endpoint];
            detection.totalBytes = totalBytes;
            detection.method = "encrypted_channel";
            detection.confidence = std::min(1.0, 0.5 + (static_cast<double>(totalBytes) / (1024.0 * 1024.0 * 1024.0)));
            detections.push_back(detection);
        }
    }

    return detections;
}

std::vector<Correlation> NetworkCorrelation::correlateNetworkActivity(const std::vector<std::string>& eventIds) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Correlation> correlations;

    if (eventIds.size() < 2) return correlations;

    // Gather specified events
    std::vector<NetworkEvent> targetEvents;
    for (const auto& id : eventIds) {
        auto it = events_.find(id);
        if (it != events_.end()) {
            targetEvents.push_back(it->second);
        }
    }

    if (targetEvents.size() < 2) return correlations;

    // Correlate by shared destination
    std::map<std::string, std::vector<std::string>> byDest;
    for (const auto& evt : targetEvents) {
        byDest[evt.destIP].push_back(evt.id);
    }

    for (const auto& [dest, ids] : byDest) {
        if (ids.size() >= 2) {
            Correlation corr;
            corr.id = "NETCORR-" + std::to_string(correlations.size() + 1);
            corr.eventIds = ids;
            corr.description = "Multiple network events targeting " + dest;
            corr.confidence = std::min(1.0, 0.4 + (ids.size() * 0.15));
            corr.severity = "medium";
            correlations.push_back(corr);
        }
    }

    return correlations;
}

std::vector<std::string> NetworkCorrelation::getSuspiciousDNSQueries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> suspicious;

    for (const auto& [id, evt] : events_) {
        if (!evt.dnsQuery.empty() && isDGADomain(evt.dnsQuery)) {
            suspicious.push_back(evt.dnsQuery);
        }
    }

    return suspicious;
}

size_t NetworkCorrelation::getEventCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_.size();
}

size_t NetworkCorrelation::getUniqueEndpoints() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return eventsByEndpoint_.size();
}

} // namespace ThreatOne::XDR
