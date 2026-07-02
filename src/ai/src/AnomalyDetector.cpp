#include "ai/AnomalyDetector.h"

#include <cmath>
#include <sstream>
#include <algorithm>
#include <numeric>
#include <cstdint>
#include <mutex>
#include <string>

namespace ThreatOne::AI {

AnomalyDetector::AnomalyDetector(size_t defaultWindowSize)
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("AnomalyDetector"))
    , defaultWindowSize_(defaultWindowSize) {
    logger_.info("AnomalyDetector initialized with window size {}", defaultWindowSize_);
}

void AnomalyDetector::addDataPoint(const std::string& featureName, double value) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& stats = featureStats_[featureName];
    updateStatistics(stats, value);

    // Maintain sliding window
    stats.recentValues.push_back(value);
    if (stats.recentValues.size() > defaultWindowSize_) {
        stats.recentValues.pop_front();
    }
}

AnomalyResult AnomalyDetector::detectZScore(const std::string& featureName,
                                              double value,
                                              double threshold) const {
    std::lock_guard<std::mutex> lock(mutex_);

    AnomalyResult result;
    result.method = "zscore";

    auto it = featureStats_.find(featureName);
    if (it == featureStats_.end() || it->second.count < 10) {
        result.isAnomaly = false;
        result.anomalyScore = 0.0;
        result.details = "Insufficient data for z-score detection";
        return result;
    }

    const auto& stats = it->second;
    double stddev = getStdDev(stats);

    if (stddev < 1e-10) {
        // If standard deviation is essentially zero, any different value is anomalous
        result.isAnomaly = (std::abs(value - stats.mean) > 1e-10);
        result.anomalyScore = result.isAnomaly ? 10.0 : 0.0;
        result.details = "Zero variance detected";
        return result;
    }

    double zScore = std::abs(value - stats.mean) / stddev;
    result.anomalyScore = zScore;
    result.isAnomaly = (zScore > threshold);

    std::ostringstream details;
    details << "z-score=" << zScore << " (threshold=" << threshold
            << ", mean=" << stats.mean << ", stddev=" << stddev
            << ", value=" << value << ")";
    result.details = details.str();

    if (result.isAnomaly) {
        logger_.debug("Z-score anomaly detected for {}: score={:.3f}", featureName, zScore);
    }

    return result;
}

AnomalyResult AnomalyDetector::detectMovingAverage(const std::string& featureName,
                                                     double value,
                                                     size_t windowSize) const {
    std::lock_guard<std::mutex> lock(mutex_);

    AnomalyResult result;
    result.method = "moving_average";

    auto it = featureStats_.find(featureName);
    if (it == featureStats_.end() || it->second.recentValues.size() < windowSize) {
        result.isAnomaly = false;
        result.anomalyScore = 0.0;
        result.details = "Insufficient data for moving average detection";
        return result;
    }

    const auto& recentValues = it->second.recentValues;

    // Compute moving average over the last windowSize values
    double sum = 0.0;
    size_t startIdx = recentValues.size() - windowSize;
    for (size_t i = startIdx; i < recentValues.size(); ++i) {
        sum += recentValues[i];
    }
    double movingAvg = sum / static_cast<double>(windowSize);

    // Compute standard deviation of the window
    double varSum = 0.0;
    for (size_t i = startIdx; i < recentValues.size(); ++i) {
        double diff = recentValues[i] - movingAvg;
        varSum += diff * diff;
    }
    double windowStdDev = std::sqrt(varSum / static_cast<double>(windowSize));

    // Deviation from moving average
    double deviation = std::abs(value - movingAvg);
    double score = (windowStdDev > 1e-10) ? deviation / windowStdDev : 0.0;

    result.anomalyScore = score;
    result.isAnomaly = (score > 2.5); // 2.5 standard deviations from moving average

    std::ostringstream details;
    details << "moving_avg=" << movingAvg << ", window_stddev=" << windowStdDev
            << ", deviation=" << deviation << ", score=" << score;
    result.details = details.str();

    return result;
}

AnomalyResult AnomalyDetector::detectIsolationForest(const FeatureVector& features) const {
    std::lock_guard<std::mutex> lock(mutex_);

    AnomalyResult result;
    result.method = "isolation_forest";

    if (featureStats_.empty()) {
        result.isAnomaly = false;
        result.anomalyScore = 0.0;
        result.details = "No baseline data available";
        return result;
    }

    double totalScore = computeIsolationScore(features);
    result.anomalyScore = totalScore;
    result.isAnomaly = (totalScore > 0.6); // Threshold for anomaly

    std::ostringstream details;
    details << "isolation_score=" << totalScore
            << " (threshold=0.6, features_evaluated=" << features.size() << ")";
    result.details = details.str();

    if (result.isAnomaly) {
        logger_.debug("Isolation forest anomaly detected: score={:.3f}", totalScore);
    }

    return result;
}

FeatureStatistics AnomalyDetector::getBaseline(const std::string& featureName) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = featureStats_.find(featureName);
    if (it != featureStats_.end()) {
        return it->second;
    }
    return FeatureStatistics{};
}

bool AnomalyDetector::hasBaseline(const std::string& featureName,
                                    uint64_t minSamples) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = featureStats_.find(featureName);
    if (it == featureStats_.end()) {
        return false;
    }
    return it->second.count >= minSamples;
}

void AnomalyDetector::resetFeature(const std::string& featureName) {
    std::lock_guard<std::mutex> lock(mutex_);
    featureStats_.erase(featureName);
}

void AnomalyDetector::resetAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    featureStats_.clear();
}

size_t AnomalyDetector::getTrackedFeatureCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return featureStats_.size();
}

void AnomalyDetector::updateStatistics(FeatureStatistics& stats, double value) {
    // Welford's online algorithm for computing running mean and variance
    stats.count++;

    if (stats.count == 1) {
        stats.mean = value;
        stats.m2 = 0.0;
        stats.min = value;
        stats.max = value;
    } else {
        double delta = value - stats.mean;
        stats.mean += delta / static_cast<double>(stats.count);
        double delta2 = value - stats.mean;
        stats.m2 += delta * delta2;

        stats.min = std::min(stats.min, value);
        stats.max = std::max(stats.max, value);
    }
}

double AnomalyDetector::getVariance(const FeatureStatistics& stats) const {
    if (stats.count < 2) {
        return 0.0;
    }
    return stats.m2 / static_cast<double>(stats.count - 1);
}

double AnomalyDetector::getStdDev(const FeatureStatistics& stats) const {
    return std::sqrt(getVariance(stats));
}

double AnomalyDetector::computeIsolationScore(const FeatureVector& features) const {
    // Simplified isolation forest: compute average normalized path length
    // Shorter path = more isolated = more anomalous
    if (features.empty()) {
        return 0.0;
    }

    double totalPathLength = 0.0;
    int evaluatedFeatures = 0;

    for (const auto& [featureName, value] : features) {
        auto it = featureStats_.find(featureName);
        if (it == featureStats_.end() || it->second.count < 5) {
            continue;
        }

        const auto& stats = it->second;
        double stddev = getStdDev(stats);
        double pathLength = computePathLength(value, stats.mean, stddev, stats.count);
        totalPathLength += pathLength;
        evaluatedFeatures++;
    }

    if (evaluatedFeatures == 0) {
        return 0.0;
    }

    // Average path length, normalized to [0, 1] range
    // Lower average path = more anomalous
    double avgPathLength = totalPathLength / static_cast<double>(evaluatedFeatures);

    // Convert to anomaly score (0 = normal, 1 = highly anomalous)
    // Using the formula: score = 2^(-avgPathLength / c(n))
    // where c(n) is the average path length of unsuccessful search in BST
    double cn = 2.0 * (std::log(static_cast<double>(evaluatedFeatures)) + 0.5772) - 
                2.0 * (static_cast<double>(evaluatedFeatures) - 1.0) / 
                static_cast<double>(evaluatedFeatures);
    if (cn < 1.0) cn = 1.0;

    double score = std::pow(2.0, -avgPathLength / cn);
    return std::clamp(score, 0.0, 1.0);
}

double AnomalyDetector::computePathLength(double value, double mean,
                                            double stddev, uint64_t sampleCount) const {
    // Simulate isolation: how many splits needed to isolate this point
    // Points far from the mean need fewer splits (shorter path = more anomalous)
    if (stddev < 1e-10 || sampleCount < 2) {
        return 1.0;
    }

    double zScore = std::abs(value - mean) / stddev;

    // Map z-score to estimated path length
    // Higher z-score = easier to isolate = shorter path
    // Normal points (z < 1) take ~log2(n) splits
    // Anomalous points (z > 3) take very few splits
    double maxPath = std::log2(static_cast<double>(sampleCount));
    if (maxPath < 1.0) maxPath = 1.0;

    double pathLength = maxPath * std::exp(-zScore * 0.5);
    return std::max(pathLength, 0.1);
}

} // namespace ThreatOne::AI
