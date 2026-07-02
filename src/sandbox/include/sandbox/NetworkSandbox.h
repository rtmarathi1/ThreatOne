#pragma once

#include "sandbox/ISandboxEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Sandbox {

struct DNSQuery {
    std::string id;
    std::string domain;
    std::string queryType;  // A, AAAA, MX, CNAME, TXT
    std::string response;
    std::string timestamp;
    bool simulated = true;
};

struct HTTPRequest {
    std::string id;
    std::string method;
    std::string url;
    std::string host;
    int statusCode = 0;
    uint64_t requestSize = 0;
    uint64_t responseSize = 0;
    std::string userAgent;
    std::string timestamp;
};

struct C2Communication {
    std::string id;
    std::string serverAddress;
    int port = 0;
    std::string protocol;
    std::string beaconPattern;
    uint64_t dataTransferred = 0;
    std::string timestamp;
    double confidence = 0.0;
};

struct NetworkSimConfig {
    bool simulateDNS = true;
    bool simulateHTTP = true;
    bool captureRawPackets = false;
    std::string defaultDNSResponse = "10.0.0.1";
    int defaultHTTPStatus = 200;
    std::vector<std::string> blockedDomains;
};

class NetworkSandbox {
public:
    NetworkSandbox();
    ~NetworkSandbox() = default;

    // Configuration
    void setSimulationConfig(const NetworkSimConfig& config);
    [[nodiscard]] NetworkSimConfig getSimulationConfig() const;

    // DNS simulation
    std::string recordDNSQuery(const std::string& sampleId, const std::string& domain,
                               const std::string& queryType);
    [[nodiscard]] std::vector<DNSQuery> getDNSQueries(const std::string& sampleId) const;
    void setDNSResponse(const std::string& domain, const std::string& response);
    std::string resolveDNS(const std::string& domain) const;

    // HTTP capture
    std::string recordHTTPRequest(const std::string& sampleId, const std::string& method,
                                  const std::string& url);
    [[nodiscard]] std::vector<HTTPRequest> getHTTPRequests(const std::string& sampleId) const;

    // C2 detection
    std::string recordC2Communication(const std::string& sampleId, const std::string& server,
                                      int port, const std::string& protocol);
    [[nodiscard]] std::vector<C2Communication> getC2Communications(const std::string& sampleId) const;
    bool detectC2Pattern(const std::string& sampleId) const;

    // Network activity conversion
    [[nodiscard]] std::vector<NetworkActivity> getNetworkActivities(const std::string& sampleId) const;

    // Statistics
    [[nodiscard]] uint64_t getTotalDNSQueries() const;
    [[nodiscard]] uint64_t getTotalHTTPRequests() const;
    [[nodiscard]] uint64_t getTotalC2Detected() const;

private:
    std::string generateId(const std::string& prefix);
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    NetworkSimConfig config_;
    std::unordered_map<std::string, std::string> dnsOverrides_; // domain -> response
    std::unordered_map<std::string, std::vector<DNSQuery>> dnsQueries_;
    std::unordered_map<std::string, std::vector<HTTPRequest>> httpRequests_;
    std::unordered_map<std::string, std::vector<C2Communication>> c2Communications_;
    int nextDnsId_ = 1;
    int nextHttpId_ = 1;
    int nextC2Id_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Sandbox
