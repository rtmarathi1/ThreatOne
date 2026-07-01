#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <chrono>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::Network {

enum class IDSAction {
    Alert,
    Drop,
    Log
};

struct IDSRule {
    std::string id;
    std::string name;
    std::string protocol;
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort = 0;
    uint16_t destPort = 0;
    std::string contentPattern;
    IDSAction action = IDSAction::Alert;
    int threshold = 1;
    int window = 60; // seconds
};

struct PacketInfo {
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort = 0;
    uint16_t destPort = 0;
    std::string protocol;
    std::string payload;
    bool synFlag = false;
};

struct IDSAlert {
    std::string ruleId;
    std::string ruleName;
    IDSAction action;
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort = 0;
    uint16_t destPort = 0;
    std::string description;
    std::chrono::steady_clock::time_point timestamp;
};

class IntrusionDetector {
public:
    /// Maximum number of alerts retained in memory. When this limit is reached,
    /// the oldest alerts are evicted to make room for new ones.
    static constexpr size_t kMaxAlerts = 10000;

    IntrusionDetector();

    void addRule(const IDSRule& rule);
    void removeRule(const std::string& ruleId);
    std::vector<IDSRule> getRules() const;

    std::vector<IDSAlert> evaluate(const PacketInfo& packet);

    /// Detect a port scan from the given source IP. The caller must invoke this
    /// once per observed connection attempt (or batch of attempts via the ports
    /// vector). The threshold is >10 unique destination ports within 60 seconds.
    bool detectPortScan(const std::string& sourceIP, const std::vector<uint16_t>& ports);

    /// Detect a SYN flood targeting destIP. Each invocation registers one event.
    /// Callers must invoke this method once per observed SYN packet for the
    /// threshold semantics to be meaningful. The `count` parameter specifies how
    /// many events within `windowSeconds` constitute a flood.
    bool detectSYNFlood(const std::string& destIP, int count, int windowSeconds);

    /// Detect brute-force login attempts. Each invocation registers one failed
    /// authentication event. Callers must invoke this once per failed attempt.
    /// `failCount` specifies the threshold within `windowSeconds`.
    bool detectBruteForce(const std::string& destIP, uint16_t destPort, int failCount, int windowSeconds);

    std::vector<IDSAlert> getAlerts() const;
    void clearAlerts();
    size_t getAlertCount() const;

private:
    struct ConnectionAttempt {
        std::chrono::steady_clock::time_point timestamp;
        uint16_t port = 0;
    };

    bool matchesRule(const IDSRule& rule, const PacketInfo& packet) const;
    void pruneOldEntries();
    void appendAlert(const IDSAlert& alert);

    mutable std::mutex mutex_;
    std::vector<IDSRule> rules_;
    std::vector<IDSAlert> alerts_;

    // Tracking for detection
    std::unordered_map<std::string, std::vector<ConnectionAttempt>> portScanTracker_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> synFloodTracker_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> bruteForceTracker_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Network
