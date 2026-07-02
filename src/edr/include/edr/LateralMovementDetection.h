#pragma once

#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <deque>
#include <mutex>
#include <unordered_set>
#include <unordered_map>

#include "edr/IEDREngine.h"
#include "core/Logger.h"
#include <cstdint>

namespace ThreatOne::EDR {

// Network event for lateral movement analysis
struct NetworkEvent {
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort = 0;
    uint16_t destPort = 0;
    std::string protocol;     // "tcp", "udp", "ssh", etc.
    std::string processName;
    uint64_t pid = 0;
    uint64_t bytesTransferred = 0;
    std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
};

class LateralMovementDetection {
public:
    LateralMovementDetection();
    ~LateralMovementDetection() = default;

    // Analyze a network connection for lateral movement indicators
    [[nodiscard]] std::optional<LateralMovementIndicator> analyzeConnection(const NetworkEvent& event);

    // Add a known/baseline connection (normal traffic)
    void addBaselineConnection(const std::string& destIP, uint16_t destPort);

    // Detect credential file access
    [[nodiscard]] std::optional<LateralMovementIndicator> detectCredentialAccess(
        const std::string& filePath, const std::string& processName) const;

    // Detect remote execution patterns
    [[nodiscard]] std::optional<LateralMovementIndicator> detectRemoteExecution(
        const std::string& commandLine, const std::string& processName) const;

    // Configuration
    void setBruteForceThreshold(size_t attempts);
    void setBruteForceWindow(std::chrono::seconds window);

    // Clear state
    void clear();

private:
    [[nodiscard]] bool isInternalIP(const std::string& ip) const;
    [[nodiscard]] bool isBaselineConnection(const std::string& destIP, uint16_t destPort) const;
    [[nodiscard]] bool isSshBruteForce(const std::string& destIP) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    // Baseline connections
    struct BaselineEntry {
        std::string destIP;
        uint16_t destPort;
    };
    std::vector<BaselineEntry> baseline_;

    // SSH attempt tracking
    struct ConnectionAttempt {
        std::string destIP;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::deque<ConnectionAttempt> sshAttempts_;

    // Credential file paths
    std::vector<std::string> credentialPaths_;

    // Remote execution tools
    std::vector<std::string> remoteExecPatterns_;

    // Configuration
    size_t bruteForceThreshold_ = 5;
    std::chrono::seconds bruteForceWindow_{60};

    // Known internal connections
    std::unordered_set<std::string> knownInternalIPs_;
};

} // namespace ThreatOne::EDR
