#pragma once

#include "xdr/IXDREngine.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <functional>

namespace ThreatOne::XDR {

// Represents a node in a process tree for endpoint correlation
struct ProcessNode {
    std::string processId;
    std::string parentProcessId;
    std::string processName;
    std::string commandLine;
    std::string timestamp;
    std::string endpointId;
    std::vector<std::string> childProcessIds;
};

// Represents a detected attack chain on an endpoint
struct AttackChain {
    std::string id;
    std::string endpointId;
    std::vector<std::string> eventIds;
    std::string description;
    std::string severity;
    double confidence = 0.0;
    std::vector<std::string> tactics;  // MITRE ATT&CK tactics
};

class EndpointCorrelation {
public:
    EndpointCorrelation();
    ~EndpointCorrelation() = default;

    // Event submission and correlation
    std::string submitEvent(const EndpointEvent& event);
    std::vector<Correlation> correlateByEndpoint(const std::vector<std::string>& eventIds);

    // Process tree analysis
    void addProcessNode(const ProcessNode& node);
    [[nodiscard]] std::vector<ProcessNode> getProcessTree(const std::string& rootProcessId) const;
    [[nodiscard]] bool isProcessSuspicious(const std::string& processId) const;

    // Attack chain detection
    [[nodiscard]] std::vector<AttackChain> detectAttackChains(const std::string& endpointId) const;

    // Event access
    [[nodiscard]] EndpointEvent getEvent(const std::string& eventId) const;
    [[nodiscard]] std::vector<EndpointEvent> getEventsByEndpoint(const std::string& endpointId) const;
    [[nodiscard]] size_t getEventCount() const;

    // Severity utilities
    [[nodiscard]] int severityToInt(const std::string& severity) const;
    [[nodiscard]] bool eventsWithinTimeWindow(const EndpointEvent& a, const EndpointEvent& b, int windowSeconds = 300) const;

private:
    std::string generateEventId();
    std::string generateChainId();

    mutable std::mutex mutex_;
    std::map<std::string, EndpointEvent> events_;
    std::map<std::string, ProcessNode> processTree_;
    std::map<std::string, std::vector<std::string>> eventsByEndpoint_;  // endpointId -> eventIds
    int nextEventId_ = 1;
    int nextChainId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::XDR
