#pragma once

#include <string>
#include <vector>
#include <mutex>

#include "core/Logger.h"
#include <utility>

namespace ThreatOne::AI {

// Result of attack likelihood prediction
struct PredictionResult {
    double likelihood = 0.0;     // 0.0 to 1.0
    std::string timeframe;
    std::string predictedThreatType;
    double confidence = 0.0;
    std::vector<std::string> reasoning;
};

// Threat intelligence context for predictions
struct ThreatIntelligence {
    std::vector<std::string> activeCampaigns;
    std::vector<std::string> knownVulnerabilities;
    std::vector<std::string> industryTargeting;
};

class PredictionEngine {
public:
    PredictionEngine();
    ~PredictionEngine() = default;

    // Predict attack likelihood from multiple data sources
    [[nodiscard]] PredictionResult predictAttackLikelihood(
        const ThreatIntelligence& intel,
        const std::vector<std::string>& vulnerabilities,
        const std::vector<double>& history) const;

    // Predict the next likely target based on attack history
    [[nodiscard]] std::string predictNextTarget(
        const std::vector<std::string>& history) const;

    // Assess exposure level from vulnerability list
    [[nodiscard]] double assessExposure(
        const std::vector<std::string>& vulnerabilities) const;

    // Get historical trend for a given period (simple linear regression)
    [[nodiscard]] std::vector<double> getHistoricalTrend(
        const std::vector<double>& eventCounts) const;

private:
    Core::ModuleLogger logger_;

    // Weighted formula components
    [[nodiscard]] double computeVulnerabilityScore(
        const std::vector<std::string>& vulnerabilities) const;

    [[nodiscard]] double computeHistoricalFrequency(
        const std::vector<double>& history) const;

    [[nodiscard]] double computeIntelCorrelation(
        const ThreatIntelligence& intel,
        const std::vector<std::string>& vulnerabilities) const;

    // Simple linear regression on event counts
    [[nodiscard]] std::pair<double, double> linearRegression(
        const std::vector<double>& values) const;

    // Determine predicted threat type from intel context
    [[nodiscard]] std::string determineThreatType(
        const ThreatIntelligence& intel) const;

    // Clamp value to [0.0, 1.0]
    [[nodiscard]] static double clamp01(double value);
};

} // namespace ThreatOne::AI
