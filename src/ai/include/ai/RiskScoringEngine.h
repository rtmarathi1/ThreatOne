#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::AI {

// Input factors for risk calculation (each 0-100)
struct RiskFactors {
    double fileReputation = 0.0;
    double behaviorScore = 0.0;
    double networkRisk = 0.0;
    double vulnerabilityScore = 0.0;
};

// Configurable weights for each factor (must sum to 1.0)
struct RiskWeights {
    double file = 0.3;
    double behavior = 0.3;
    double network = 0.2;
    double vulnerability = 0.2;
};

// Result of risk calculation
struct RiskResult {
    double overallScore = 0.0;
    std::string riskLevel;
    std::vector<std::string> contributingFactors;
    std::map<std::string, double> breakdown;
};

class RiskScoringEngine {
public:
    RiskScoringEngine();
    ~RiskScoringEngine() = default;

    // Calculate overall risk from multiple factors
    [[nodiscard]] RiskResult calculateRisk(const RiskFactors& factors) const;

    // Set custom weights for risk calculation
    void setWeights(const RiskWeights& weights);

    // Get the current weights
    [[nodiscard]] RiskWeights getWeights() const;

    // Map a numeric score to a risk level string
    [[nodiscard]] static std::string getRiskLevel(double score);

    // Get per-factor breakdown showing each factor's weighted contribution
    [[nodiscard]] std::map<std::string, double> getBreakdown(const RiskFactors& factors) const;

private:
    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;
    RiskWeights weights_;

    // Clamp a value to [0, 100]
    [[nodiscard]] static double clamp(double value);
};

} // namespace ThreatOne::AI
