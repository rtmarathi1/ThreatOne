#include "ai/RiskScoringEngine.h"

#include <algorithm>
#include <cmath>
#include <map>
#include <mutex>
#include <string>

namespace ThreatOne::AI {

RiskScoringEngine::RiskScoringEngine()
    : logger_(Core::Logger::instance().getModuleLogger("RiskScoringEngine"))
    , weights_{}
{
    logger_.info("RiskScoringEngine initialized with default weights");
}

RiskResult RiskScoringEngine::calculateRisk(const RiskFactors& factors) const {
    std::lock_guard<std::mutex> lock(mutex_);

    RiskResult result;

    // Clamp all input factors to [0, 100]
    double fileFactor = clamp(factors.fileReputation);
    double behaviorFactor = clamp(factors.behaviorScore);
    double networkFactor = clamp(factors.networkRisk);
    double vulnFactor = clamp(factors.vulnerabilityScore);

    // Calculate weighted score
    result.overallScore = clamp(
        fileFactor * weights_.file +
        behaviorFactor * weights_.behavior +
        networkFactor * weights_.network +
        vulnFactor * weights_.vulnerability
    );

    // Determine risk level
    result.riskLevel = getRiskLevel(result.overallScore);

    // Build breakdown
    result.breakdown["fileReputation"] = fileFactor * weights_.file;
    result.breakdown["behaviorScore"] = behaviorFactor * weights_.behavior;
    result.breakdown["networkRisk"] = networkFactor * weights_.network;
    result.breakdown["vulnerabilityScore"] = vulnFactor * weights_.vulnerability;

    // Contributing factors are those above 50
    const double contributionThreshold = 50.0;
    if (fileFactor > contributionThreshold) {
        result.contributingFactors.push_back("fileReputation");
    }
    if (behaviorFactor > contributionThreshold) {
        result.contributingFactors.push_back("behaviorScore");
    }
    if (networkFactor > contributionThreshold) {
        result.contributingFactors.push_back("networkRisk");
    }
    if (vulnFactor > contributionThreshold) {
        result.contributingFactors.push_back("vulnerabilityScore");
    }

    logger_.debug("Risk calculated: score={:.1f}, level={}", result.overallScore, result.riskLevel);
    return result;
}

void RiskScoringEngine::setWeights(const RiskWeights& weights) {
    std::lock_guard<std::mutex> lock(mutex_);
    weights_ = weights;
    logger_.info("Risk weights updated: file={:.2f}, behavior={:.2f}, network={:.2f}, vuln={:.2f}",
                 weights_.file, weights_.behavior, weights_.network, weights_.vulnerability);
}

RiskWeights RiskScoringEngine::getWeights() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return weights_;
}

std::string RiskScoringEngine::getRiskLevel(double score) {
    double clamped = clamp(score);
    if (clamped <= 20.0) return "minimal";
    if (clamped <= 40.0) return "low";
    if (clamped <= 60.0) return "medium";
    if (clamped <= 80.0) return "high";
    return "critical";
}

std::map<std::string, double> RiskScoringEngine::getBreakdown(const RiskFactors& factors) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::map<std::string, double> breakdown;
    breakdown["fileReputation"] = clamp(factors.fileReputation) * weights_.file;
    breakdown["behaviorScore"] = clamp(factors.behaviorScore) * weights_.behavior;
    breakdown["networkRisk"] = clamp(factors.networkRisk) * weights_.network;
    breakdown["vulnerabilityScore"] = clamp(factors.vulnerabilityScore) * weights_.vulnerability;
    return breakdown;
}

double RiskScoringEngine::clamp(double value) {
    return std::clamp(value, 0.0, 100.0);
}

} // namespace ThreatOne::AI
