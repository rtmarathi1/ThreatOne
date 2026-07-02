#pragma once

#include "analytics/IAnalyticsEngine.h"
#include "analytics/BehaviorAnalyticsEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <deque>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace ThreatOne::Analytics {

class AnalyticsEngine : public IAnalyticsEngine {
public:
    AnalyticsEngine();
    ~AnalyticsEngine() override = default;

    std::vector<AnalyticsMetric> getMetrics() override;
    std::vector<TrendData> getTrends(const std::string& period) override;
    std::vector<ThreatSummary> getTopThreats(int limit) override;
    double getRiskScore() override;
    SecurityPosture getSecurityPosture() override;

    // Methods to record events for analytics
    void recordThreat(const std::string& name, const std::string& severity);
    void recordScan(double coverage);

private:
    mutable std::mutex mutex_;
    ThreatOne::Core::ModuleLogger logger_;
    BehaviorAnalyticsEngine behaviorEngine_;

    // Internal state
    struct ThreatRecord {
        std::string name;
        std::string severity;
        std::string timestamp;
    };

    std::deque<ThreatRecord> threatHistory_;
    std::deque<double> scanCoverageHistory_;
    std::deque<double> metricHistory_;  // Generic metric values over time

    uint64_t totalThreatsDetected_ = 0;
    uint64_t totalScansCompleted_ = 0;
    double lastScanCoverage_ = 0.0;
    double detectionRate_ = 0.95;  // Assumed baseline

    static constexpr size_t MAX_HISTORY_SIZE = 1000;

    // Internal helpers
    [[nodiscard]] std::string getCurrentTimestamp() const;
    [[nodiscard]] double computeOverallRiskScore() const;
};

} // namespace ThreatOne::Analytics
