#pragma once

#include "ai/IAIEngine.h"
#include "core/Logger.h"

namespace ThreatOne::AI {

class AIEngine : public IAIEngine {
public:
    AIEngine();
    ~AIEngine() override = default;

    ThreatClassification classifyThreat(const std::string& data) override;
    RiskPrediction predictRisk(const std::string& context) override;
    PatternAnalysis analyzePattern(const std::string& data) override;
    IncidentSummary summarizeIncident(const std::string& incidentId) override;
    std::vector<Recommendation> getRecommendations(const std::string& context) override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::AI
