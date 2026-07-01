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
    IntrusionDetector();

    void addRule(const IDSRule& rule);
    void removeRule(const std::string& ruleId);
    std::vector<IDSRule> getRules() const;

    std::vector<IDSAlert> evaluate(const PacketInfo& packet);
    bool detectPortScan(const std::string& sourceIP, const std::vector<uint16_t>& ports);
    bool detectSYNFlood(const std::string& destIP, int count, int windowSeconds);
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
