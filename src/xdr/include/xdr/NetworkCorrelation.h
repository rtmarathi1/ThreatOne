#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <set>

namespace ThreatOne::XDR {

// Represents a network connection event
struct NetworkEvent {
    std::string id;
    std::string sourceIP;
    std::string destIP;
    int sourcePort = 0;
    int destPort = 0;
    std::string protocol;  // TCP, UDP, DNS, HTTP
    std::string timestamp;
    std::string endpointId;
    size_t bytesTransferred = 0;
    std::string direction;  // "inbound", "outbound"
    std::string dnsQuery;   // For DNS events
};

// Represents detected lateral movement
struct LateralMovement {
    std::string id;
    std::string sourceEndpoint;
    std::vector<std::string> targetEndpoints;
    std::string technique;
    std::string timestamp;
    double confidence = 0.0;
};

// Represents detected C2 communication
struct C2Detection {
    std::string id;
    std::string endpointId;
    std::string destIP;
    int destPort = 0;
    std::string beaconInterval;
    double confidence = 0.0;
    std::vector<std::string> indicators;
};

// Represents detected data exfiltration
struct ExfiltrationDetection {
    std::string id;
    std::string endpointId;
    std::string destIP;
    size_t totalBytes = 0;
    std::string method;  // "dns_tunnel", "http_post", "encrypted_channel"
    double confidence = 0.0;
};

class NetworkCorrelation {
public:
    NetworkCorrelation();
    ~NetworkCorrelation() = default;

    // Network event submission
    std::string submitNetworkEvent(const NetworkEvent& event);
    [[nodiscard]] std::vector<NetworkEvent> getNetworkEvents(const std::string& endpointId) const;

    // Lateral movement detection
    [[nodiscard]] std::vector<LateralMovement> detectLateralMovement() const;

    // C2 detection
    [[nodiscard]] std::vector<C2Detection> detectC2Communication() const;

    // Data exfiltration detection
    [[nodiscard]] std::vector<ExfiltrationDetection> detectExfiltration() const;

    // Correlation with endpoint events
    [[nodiscard]] std::vector<Correlation> correlateNetworkActivity(const std::vector<std::string>& eventIds) const;

    // DNS analysis
    [[nodiscard]] std::vector<std::string> getSuspiciousDNSQueries() const;

    // Stats
    [[nodiscard]] size_t getEventCount() const;
    [[nodiscard]] size_t getUniqueEndpoints() const;

private:
    std::string generateEventId();
    std::string generateDetectionId();
    bool isInternalIP(const std::string& ip) const;
    bool isDGADomain(const std::string& domain) const;

    mutable std::mutex mutex_;
    std::map<std::string, NetworkEvent> events_;
    std::map<std::string, std::vector<std::string>> eventsByEndpoint_;
    std::map<std::string, std::vector<std::string>> connectionsByDest_;
    int nextEventId_ = 1;
    int nextDetectionId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
