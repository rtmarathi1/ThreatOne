#pragma once

#include <string>
#include <vector>
#include <deque>
#include <chrono>
#include <mutex>
#include <cstdint>

#include "core/Logger.h"

namespace ThreatOne::EDR {

// Event structure for the behavior analyzer
struct EDREvent {
    std::string type;        // "file_rename", "file_write", "process_exec", "network_out", etc.
    std::string source;      // Process name or module that generated the event
    std::string path;        // File path or network endpoint
    std::string details;     // Additional details (e.g., destination IP, command line)
    uint64_t pid = 0;
    double entropy = 0.0;    // For file write events, entropy of data
    uint64_t dataSize = 0;   // Size of data involved
    std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
};

// Alert generated from behavior analysis
struct BehaviorAlert {
    std::string patternType;   // "ransomware", "privilege_escalation", "data_exfiltration"
    std::string description;
    std::string severity;      // "low", "medium", "high", "critical"
    std::vector<std::string> relatedEvents;
    std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
};

class BehaviorAnalyzer {
public:
    explicit BehaviorAnalyzer(size_t windowSize = 1000);
    ~BehaviorAnalyzer() = default;

    // Add an event to the sliding window
    void addEvent(const EDREvent& event);

    // Analyze all events in window for known malicious patterns
    [[nodiscard]] std::vector<BehaviorAlert> analyzePatterns() const;

    // Individual pattern detectors
    [[nodiscard]] std::vector<BehaviorAlert> detectRansomwareBehavior() const;
    [[nodiscard]] std::vector<BehaviorAlert> detectPrivilegeEscalation() const;
    [[nodiscard]] std::vector<BehaviorAlert> detectDataExfiltration() const;

    // Configuration
    void setWindowSize(size_t size);
    [[nodiscard]] size_t getWindowSize() const;
    [[nodiscard]] size_t getEventCount() const;

    // Clear the event window
    void clear();

private:
    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;
    std::deque<EDREvent> events_;
    size_t windowSize_;
};

} // namespace ThreatOne::EDR
