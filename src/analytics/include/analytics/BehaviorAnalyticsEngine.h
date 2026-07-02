#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <deque>
#include <mutex>
#include <chrono>
#include <set>

#include "core/Logger.h"
#include <cstdint>
#include <utility>

namespace ThreatOne::Analytics {

// An event for user behavior analysis
struct UserEvent {
    std::string userId;
    std::string eventType;
    std::string resource;
    std::chrono::system_clock::time_point timestamp = std::chrono::system_clock::now();
    std::string details;
};

// Baseline of normal behavior for a user
struct UserBaseline {
    std::pair<int, int> normalHours = {8, 18};    // Start and end hours (24h format)
    std::vector<std::string> typicalAccessPatterns;
    double averageEventRate = 0.0;                // Events per hour
    std::vector<std::string> commonProcesses;
    double eventRateStdDev = 0.0;
    double meanHour = 12.0;
    double hourStdDev = 3.0;
    double hourM2 = 0.0;                          // Welford's M2 for online variance
    uint64_t eventCount = 0;
};

// Result of a deviation check
struct DeviationResult {
    bool isDeviation = false;
    double deviationScore = 0.0;
    std::string baselineMetric;
    double currentValue = 0.0;
    std::string description;
};

class BehaviorAnalyticsEngine {
public:
    BehaviorAnalyticsEngine();
    ~BehaviorAnalyticsEngine() = default;

    // Build a baseline from historical events for a user
    void buildBaseline(const std::string& userId, const std::vector<UserEvent>& events);

    // Detect deviation from baseline for a current event
    [[nodiscard]] DeviationResult detectDeviation(const std::string& userId,
                                                   const UserEvent& currentEvent) const;

    // Analyze time-of-day for a user event
    [[nodiscard]] DeviationResult analyzeTimeOfDay(const std::string& userId,
                                                    std::chrono::system_clock::time_point timestamp) const;

    // Analyze access pattern for a user
    [[nodiscard]] DeviationResult analyzeAccessPattern(const std::string& userId,
                                                       const std::string& resource) const;

    // Get the baseline for a user
    [[nodiscard]] UserBaseline getBaseline(const std::string& userId) const;

    // Update baseline with a new event (incremental)
    void updateBaseline(const std::string& userId, const UserEvent& event);

    // Check if a baseline exists for a user
    [[nodiscard]] bool hasBaseline(const std::string& userId) const;

    // Get number of tracked users
    [[nodiscard]] size_t getUserCount() const;

private:
    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    std::unordered_map<std::string, UserBaseline> baselines_;
    std::unordered_map<std::string, std::deque<UserEvent>> recentEvents_;

    // Internal helpers
    [[nodiscard]] double computeZScore(double value, double mean, double stdDev) const;
    [[nodiscard]] int extractHour(std::chrono::system_clock::time_point tp) const;
};

} // namespace ThreatOne::Analytics
