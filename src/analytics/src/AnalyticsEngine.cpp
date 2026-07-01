#include "analytics/AnalyticsEngine.h"

#include <algorithm>
#include <numeric>
#include <ctime>
#include <map>

namespace ThreatOne::Analytics {

AnalyticsEngine::AnalyticsEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("AnalyticsEngine")) {
    logger_.info("AnalyticsEngine initialized");
}

std::vector<AnalyticsMetric> AnalyticsEngine::getMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_.debug("getMetrics called");

    std::vector<AnalyticsMetric> metrics;
    std::string ts = getCurrentTimestamp();

    // Threats detected metric
    metrics.push_back({
        "threats_detected",
        static_cast<double>(totalThreatsDetected_),
        "count",
        ts
    });

    // Scan coverage metric
    metrics.push_back({
        "scan_coverage",
        lastScanCoverage_,
        "percent",
        ts
    });

    // Total scans completed
    metrics.push_back({
        "scans_completed",
        static_cast<double>(totalScansCompleted_),
        "count",
        ts
    });

    // Detection rate
    metrics.push_back({
        "detection_rate",
        detectionRate_ * 100.0,
        "percent",
        ts
    });

    // Active monitored users (from behavior engine)
    metrics.push_back({
        "monitored_users",
        static_cast<double>(behaviorEngine_.getUserCount()),
        "count",
        ts
    });

    return metrics;
}

std::vector<TrendData> AnalyticsEngine::getTrends(const std::string& period) {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_.debug("getTrends called: {}", period);

    std::vector<TrendData> trends;

    // Threat count trend
    if (!metricHistory_.empty()) {
        TrendData threatTrend;
        threatTrend.metric = "threats_detected";
        threatTrend.values.assign(metricHistory_.begin(), metricHistory_.end());

        // Generate timestamps (synthetic, one per data point)
        for (size_t i = 0; i < metricHistory_.size(); ++i) {
            threatTrend.timestamps.push_back("T" + std::to_string(i));
        }

        // Determine direction
        if (metricHistory_.size() >= 2) {
            double first = metricHistory_.front();
            double last = metricHistory_.back();
            if (last > first * 1.1) {
                threatTrend.direction = "increasing";
            } else if (last < first * 0.9) {
                threatTrend.direction = "decreasing";
            } else {
                threatTrend.direction = "stable";
            }
        } else {
            threatTrend.direction = "stable";
        }
        trends.push_back(threatTrend);
    }

    // Scan coverage trend
    if (!scanCoverageHistory_.empty()) {
        TrendData scanTrend;
        scanTrend.metric = "scan_coverage";
        scanTrend.values.assign(scanCoverageHistory_.begin(), scanCoverageHistory_.end());

        for (size_t i = 0; i < scanCoverageHistory_.size(); ++i) {
            scanTrend.timestamps.push_back("T" + std::to_string(i));
        }

        if (scanCoverageHistory_.size() >= 2) {
            double first = scanCoverageHistory_.front();
            double last = scanCoverageHistory_.back();
            if (last > first + 5.0) {
                scanTrend.direction = "increasing";
            } else if (last < first - 5.0) {
                scanTrend.direction = "decreasing";
            } else {
                scanTrend.direction = "stable";
            }
        } else {
            scanTrend.direction = "stable";
        }
        trends.push_back(scanTrend);
    }

    return trends;
}

std::vector<ThreatSummary> AnalyticsEngine::getTopThreats(int limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_.debug("getTopThreats called: limit={}", limit);

    // Aggregate threat counts from history
    std::map<std::string, ThreatSummary> aggregated;

    for (const auto& record : threatHistory_) {
        auto& summary = aggregated[record.name];
        summary.name = record.name;
        summary.count++;
        summary.severity = record.severity;
    }

    // Convert to vector and sort by count (descending)
    std::vector<ThreatSummary> result;
    result.reserve(aggregated.size());
    for (auto& [name, summary] : aggregated) {
        // Calculate trend as proportion of recent threats
        size_t recentCount = 0;
        size_t totalRecent = std::min(threatHistory_.size(), size_t{100});
        if (totalRecent > 0) {
            for (size_t i = threatHistory_.size() - totalRecent; i < threatHistory_.size(); ++i) {
                if (threatHistory_[i].name == name) {
                    recentCount++;
                }
            }
            summary.trend = static_cast<double>(recentCount) / static_cast<double>(totalRecent);
        }
        result.push_back(summary);
    }

    std::sort(result.begin(), result.end(),
              [](const ThreatSummary& a, const ThreatSummary& b) {
                  return a.count > b.count;
              });

    if (static_cast<int>(result.size()) > limit) {
        result.resize(static_cast<size_t>(limit));
    }

    return result;
}

double AnalyticsEngine::getRiskScore() {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_.debug("getRiskScore called");
    return computeOverallRiskScore();
}

SecurityPosture AnalyticsEngine::getSecurityPosture() {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_.debug("getSecurityPosture called");

    SecurityPosture posture;
    double riskScore = computeOverallRiskScore();

    // Overall score is inverse of risk (higher score = better security)
    posture.overallScore = std::max(0.0, 100.0 - riskScore);

    // Category scores
    // Endpoint: based on scan coverage
    posture.categoryScores["endpoint"] = lastScanCoverage_;

    // Network: baseline score adjusted by recent threat activity
    double networkScore = 80.0;
    if (!threatHistory_.empty()) {
        // Reduce score based on recent threats
        size_t recentThreats = std::min(threatHistory_.size(), size_t{10});
        networkScore -= static_cast<double>(recentThreats) * 2.0;
    }
    posture.categoryScores["network"] = std::max(0.0, networkScore);

    // Detection: based on detection rate
    posture.categoryScores["detection"] = detectionRate_ * 100.0;

    // Behavior: based on monitored users
    double behaviorScore = behaviorEngine_.getUserCount() > 0 ? 75.0 : 50.0;
    posture.categoryScores["behavior"] = behaviorScore;

    // Generate recommendations based on posture
    if (lastScanCoverage_ < 80.0) {
        posture.recommendations.push_back("Increase scan coverage to at least 80%");
    }
    if (totalThreatsDetected_ > 10) {
        posture.recommendations.push_back("Review threat response procedures");
    }
    if (behaviorEngine_.getUserCount() == 0) {
        posture.recommendations.push_back("Enable user behavior monitoring");
    }
    if (posture.overallScore < 70.0) {
        posture.recommendations.push_back("Overall security posture needs improvement");
    }
    if (posture.recommendations.empty()) {
        posture.recommendations.push_back("Continue current monitoring practices");
    }

    return posture;
}

void AnalyticsEngine::recordThreat(const std::string& name, const std::string& severity) {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_.debug("Recording threat: {} ({})", name, severity);

    ThreatRecord record;
    record.name = name;
    record.severity = severity;
    record.timestamp = getCurrentTimestamp();

    threatHistory_.push_back(record);
    if (threatHistory_.size() > MAX_HISTORY_SIZE) {
        threatHistory_.pop_front();
    }

    totalThreatsDetected_++;
    metricHistory_.push_back(static_cast<double>(totalThreatsDetected_));
    if (metricHistory_.size() > MAX_HISTORY_SIZE) {
        metricHistory_.pop_front();
    }
}

void AnalyticsEngine::recordScan(double coverage) {
    std::lock_guard<std::mutex> lock(mutex_);
    logger_.debug("Recording scan: coverage={:.1f}%", coverage);

    lastScanCoverage_ = coverage;
    totalScansCompleted_++;

    scanCoverageHistory_.push_back(coverage);
    if (scanCoverageHistory_.size() > MAX_HISTORY_SIZE) {
        scanCoverageHistory_.pop_front();
    }
}

std::string AnalyticsEngine::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf{};
    gmtime_r(&time, &tm_buf);

    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf);
}

double AnalyticsEngine::computeOverallRiskScore() const {
    // Combine multiple factors into overall risk score (0-100)
    double threatFactor = 0.0;
    double coverageFactor = 0.0;

    // Threat factor: more recent threats = higher risk
    if (!threatHistory_.empty()) {
        size_t recentWindow = std::min(threatHistory_.size(), size_t{20});
        int criticalCount = 0;
        int highCount = 0;
        for (size_t i = threatHistory_.size() - recentWindow; i < threatHistory_.size(); ++i) {
            if (threatHistory_[i].severity == "critical") criticalCount++;
            else if (threatHistory_[i].severity == "high") highCount++;
        }
        threatFactor = std::min(100.0,
            static_cast<double>(criticalCount) * 15.0 +
            static_cast<double>(highCount) * 8.0 +
            static_cast<double>(recentWindow) * 1.5);
    }

    // Coverage factor: lower coverage = higher risk
    coverageFactor = std::max(0.0, 100.0 - lastScanCoverage_);

    // Weighted combination
    double riskScore = 0.6 * threatFactor + 0.4 * coverageFactor;
    return std::min(100.0, std::max(0.0, riskScore));
}

} // namespace ThreatOne::Analytics
