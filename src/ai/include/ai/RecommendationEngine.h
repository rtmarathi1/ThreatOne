#pragma once

#include <string>
#include <vector>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::AI {

// A security recommendation
struct SecurityRecommendation {
    std::string id;
    std::string title;
    std::string description;
    int priority = 3;         // 1 (highest) to 5 (lowest)
    std::string category;
    std::string effort;       // "low", "medium", "high"
    std::string impact;       // "low", "medium", "high"
};

// Current risk posture for recommendation generation
struct RiskPosture {
    double overallRisk = 0.0;
    int openVulnerabilities = 0;
    int activeThreats = 0;
    std::vector<std::string> configGaps;
};

class RecommendationEngine {
public:
    RecommendationEngine();
    ~RecommendationEngine() = default;

    // Generate recommendations based on current risk posture
    [[nodiscard]] std::vector<SecurityRecommendation> generateRecommendations(
        const RiskPosture& posture) const;

    // Prioritize a list of recommendations (sort by priority/impact)
    [[nodiscard]] std::vector<SecurityRecommendation> prioritize(
        std::vector<SecurityRecommendation> recommendations) const;

    // Get top N recommendations for a given posture
    [[nodiscard]] std::vector<SecurityRecommendation> getTopN(
        int n, const RiskPosture& posture) const;

private:
    Core::ModuleLogger logger_;

    // Rule-based recommendation generators
    [[nodiscard]] std::vector<SecurityRecommendation> generateThreatRecommendations(
        int activeThreats) const;
    [[nodiscard]] std::vector<SecurityRecommendation> generateVulnerabilityRecommendations(
        int openVulnerabilities) const;
    [[nodiscard]] std::vector<SecurityRecommendation> generateConfigRecommendations(
        const std::vector<std::string>& configGaps) const;
    [[nodiscard]] std::vector<SecurityRecommendation> generateRiskRecommendations(
        double overallRisk) const;
};

} // namespace ThreatOne::AI
