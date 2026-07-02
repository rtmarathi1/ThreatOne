#include "threat_intel/ThreatScoring.h"

#include <algorithm>
#include <cmath>
#include <chrono>
#include <string>
#include <unordered_map>

namespace ThreatOne::ThreatIntel {

ThreatScoringEngine::ThreatScoringEngine()
    : logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.ThreatScoring")) {
    // Set default weights
    weights_["confidence"] = DEFAULT_CONFIDENCE_WEIGHT;
    weights_["source"] = DEFAULT_SOURCE_WEIGHT;
    weights_["age_decay"] = DEFAULT_AGE_DECAY_WEIGHT;
    weights_["correlation"] = DEFAULT_CORRELATION_WEIGHT;
}

ThreatScore ThreatScoringEngine::calculateScore(const IOC& ioc) const {
    return calculateScore(ioc, false, 0.0);
}

ThreatScore ThreatScoringEngine::calculateScore(
    const IOC& ioc, bool isCorrelated, double correlationStrength) const {

    ThreatScore score;

    // Base score from IOC confidence (0.0 - 1.0 -> 0 - 100)
    double baseScore = ioc.confidence * 100.0;
    score.iocConfidence = baseScore;
    score.breakdown["base_confidence"] = baseScore;

    // Source reliability weight
    double sourceWeight = getSourceReliability(ioc.source);
    score.sourceReliability = sourceWeight;
    score.breakdown["source_reliability"] = sourceWeight;

    // Age decay (exponential decay over MAX_AGE_DAYS)
    double ageDecay = computeAgeDecay(ioc.lastSeen);
    score.ageDecay = ageDecay;
    score.breakdown["age_decay"] = ageDecay;

    // Correlation boost
    double correlationBoost = 0.0;
    if (isCorrelated) {
        correlationBoost = correlationStrength * getWeight("correlation") * 20.0;
        // Cap boost at 20 points
        correlationBoost = std::min(20.0, correlationBoost);
    }
    score.correlationBoost = correlationBoost;
    score.breakdown["correlation_boost"] = correlationBoost;

    // Calculate overall score:
    // base = confidence * 100
    // Apply source weight as multiplier
    // Apply age decay
    // Add correlation boost
    double weightedScore = baseScore * sourceWeight * ageDecay;
    double overall = weightedScore + correlationBoost;

    // Clamp to 0-100
    score.overallScore = std::min(100.0, std::max(0.0, overall));
    score.breakdown["overall"] = score.overallScore;

    return score;
}

void ThreatScoringEngine::configureWeights(const std::unordered_map<std::string, double>& weights) {
    for (const auto& [factor, weight] : weights) {
        weights_[factor] = weight;
    }
    logger_.debug("Updated {} weight factors", weights.size());
}

void ThreatScoringEngine::setWeight(const std::string& factor, double weight) {
    weights_[factor] = weight;
}

double ThreatScoringEngine::getWeight(const std::string& factor) const {
    auto it = weights_.find(factor);
    if (it != weights_.end()) {
        return it->second;
    }
    return 1.0; // Default weight
}

void ThreatScoringEngine::setSourceReliability(const std::string& source, double reliability) {
    sourceReliabilities_[source] = std::min(1.0, std::max(0.0, reliability));
}

double ThreatScoringEngine::getSourceReliability(const std::string& source) const {
    auto it = sourceReliabilities_.find(source);
    if (it != sourceReliabilities_.end()) {
        return it->second;
    }
    return 0.5; // Default reliability for unknown sources
}

double ThreatScoringEngine::computeAgeDecay(
    const std::chrono::system_clock::time_point& lastSeen) const {

    // If lastSeen is epoch/default, no decay info available - assume fresh
    if (lastSeen == std::chrono::system_clock::time_point{}) {
        return 1.0;
    }

    auto now = std::chrono::system_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::hours>(now - lastSeen);
    double ageDays = static_cast<double>(age.count()) / 24.0;

    // If in the future or zero age, no decay
    if (ageDays <= 0.0) {
        return 1.0;
    }

    // Exponential decay: decay = exp(-ln(2) * ageDays / halfLife)
    // At halfLife days, decay = 0.5
    // At MAX_AGE_DAYS, decay is very small
    double decay = std::exp(-0.693147 * ageDays / DECAY_HALF_LIFE_DAYS);

    // Floor at 0.1 (never fully zero out)
    return std::max(0.1, decay);
}

} // namespace ThreatOne::ThreatIntel
