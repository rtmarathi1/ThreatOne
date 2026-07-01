#pragma once

#include <string>
#include <vector>

namespace ThreatOne::AI {

struct ThreatClassification {
    std::string category;
    double confidence = 0.0;
    std::string description;
};

struct RiskPrediction {
    double score = 0.0;
    std::string level;
    std::vector<std::string> factors;
};

struct PatternAnalysis {
    std::string patternId;
    std::string description;
    double confidence = 0.0;
    std::vector<std::string> relatedIndicators;
};

struct IncidentSummary {
    std::string summary;
    std::string severity;
    std::vector<std::string> affectedAssets;
    std::vector<std::string> timeline;
};

struct Recommendation {
    std::string action;
    std::string priority;
    std::string rationale;
};

class IAIEngine {
public:
    virtual ~IAIEngine() = default;

    virtual ThreatClassification classifyThreat(const std::string& data) = 0;
    virtual RiskPrediction predictRisk(const std::string& context) = 0;
    virtual PatternAnalysis analyzePattern(const std::string& data) = 0;
    virtual IncidentSummary summarizeIncident(const std::string& incidentId) = 0;
    virtual std::vector<Recommendation> getRecommendations(const std::string& context) = 0;
};

} // namespace ThreatOne::AI
