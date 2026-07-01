#pragma once

#include <string>
#include <vector>
#include <map>
#include <deque>
#include <mutex>
#include <cstdint>

#include "ai/FeatureExtractor.h"
#include "core/Logger.h"

namespace ThreatOne::AI {

// Result of an anomaly detection check
struct AnomalyResult {
    bool isAnomaly = false;
    double anomalyScore = 0.0;
    std::string method;            // "zscore", "moving_average", "isolation_forest"
    std::string details;
};

// Running statistics for a single feature (Welford's online algorithm)
struct FeatureStatistics {
    uint64_t count = 0;
    double mean = 0.0;
    double m2 = 0.0;              // Sum of squares of differences from current mean
    double min = 0.0;
    double max = 0.0;
    std::deque<double> recentValues;  // Sliding window of recent values
};

class AnomalyDetector {
public:
    explicit AnomalyDetector(size_t defaultWindowSize = 100);
    ~AnomalyDetector() = default;

    // Add a data point for a named feature (updates running statistics)
    void addDataPoint(const std::string& featureName, double value);

    // Z-score based anomaly detection
    [[nodiscard]] AnomalyResult detectZScore(const std::string& featureName,
                                              double value,
                                              double threshold = 3.0) const;

    // Moving average based anomaly detection
    [[nodiscard]] AnomalyResult detectMovingAverage(const std::string& featureName,
                                                     double value,
                                                     size_t windowSize = 20) const;

    // Simplified isolation forest anomaly detection
    [[nodiscard]] AnomalyResult detectIsolationForest(const FeatureVector& features) const;

    // Get current baseline statistics for a feature
    [[nodiscard]] FeatureStatistics getBaseline(const std::string& featureName) const;

    // Check if enough data has been collected for meaningful detection
    [[nodiscard]] bool hasBaseline(const std::string& featureName,
                                    uint64_t minSamples = 10) const;

    // Reset statistics for a feature
    void resetFeature(const std::string& featureName);

    // Reset all statistics
    void resetAll();

    // Get the number of tracked features
    [[nodiscard]] size_t getTrackedFeatureCount() const;

private:
    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;
    size_t defaultWindowSize_;
    std::map<std::string, FeatureStatistics> featureStats_;

    // Welford's online algorithm helpers
    void updateStatistics(FeatureStatistics& stats, double value);
    [[nodiscard]] double getVariance(const FeatureStatistics& stats) const;
    [[nodiscard]] double getStdDev(const FeatureStatistics& stats) const;

    // Isolation forest helpers
    [[nodiscard]] double computeIsolationScore(const FeatureVector& features) const;
    [[nodiscard]] double computePathLength(double value, double mean,
                                            double stddev, uint64_t sampleCount) const;
};

} // namespace ThreatOne::AI
