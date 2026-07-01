#pragma once

// ThreatOne Threat Intel - Threat Scoring Engine
// Calculates threat scores based on IOC confidence, source reliability, age, and correlation

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>

#include <core/Error.h>
#include <core/Logger.h>
#include "IOCTypes.h"

namespace ThreatOne::ThreatIntel {

// Detailed threat score breakdown
struct ThreatScore {
    double overallScore = 0.0;       // 0 - 100
    double iocConfidence = 0.0;      // Confidence component
    double sourceReliability = 0.0;  // Source reliability component
    double ageDecay = 0.0;           // Age decay factor (0.0 - 1.0)
    double correlationBoost = 0.0;   // Boost from being part of campaign
    std::unordered_map<std::string, double> breakdown; // Detailed factor breakdown
};

// Engine that scores threats based on multiple factors
class ThreatScoringEngine {
public:
    ThreatScoringEngine();

    // Calculate a threat score for an IOC
    [[nodiscard]] ThreatScore calculateScore(const IOC& ioc) const;

    // Calculate score with explicit correlation information
    [[nodiscard]] ThreatScore calculateScore(
        const IOC& ioc, bool isCorrelated, double correlationStrength = 0.0) const;

    // Configure weight factors
    void configureWeights(const std::unordered_map<std::string, double>& weights);

    // Set a single weight
    void setWeight(const std::string& factor, double weight);

    // Get current weight for a factor
    [[nodiscard]] double getWeight(const std::string& factor) const;

    // Set source reliability for a named source
    void setSourceReliability(const std::string& source, double reliability);

    // Get source reliability (defaults to 0.5 if unknown)
    [[nodiscard]] double getSourceReliability(const std::string& source) const;

private:
    double computeAgeDecay(const std::chrono::system_clock::time_point& lastSeen) const;

    std::unordered_map<std::string, double> weights_;
    std::unordered_map<std::string, double> sourceReliabilities_;
    Core::ModuleLogger logger_;

    // Default configuration
    static constexpr double DEFAULT_CONFIDENCE_WEIGHT = 1.0;
    static constexpr double DEFAULT_SOURCE_WEIGHT = 0.8;
    static constexpr double DEFAULT_AGE_DECAY_WEIGHT = 0.7;
    static constexpr double DEFAULT_CORRELATION_WEIGHT = 0.5;
    static constexpr double DECAY_HALF_LIFE_DAYS = 45.0;  // Half-life for age decay
    static constexpr double MAX_AGE_DAYS = 90.0;          // Max age before full decay
};

} // namespace ThreatOne::ThreatIntel
