#pragma once

#include "ai/IAIEngine.h"
#include "ai/FeatureExtractor.h"
#include "ai/ThreatClassifier.h"
#include "ai/RiskScoringEngine.h"
#include "ai/AnomalyDetector.h"
#include "ai/NLPProcessor.h"
#include "ai/RecommendationEngine.h"
#include "ai/AutoInvestigation.h"
#include "ai/PredictionEngine.h"
#include "core/Logger.h"

#include <memory>
#include <mutex>

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
    mutable std::mutex mutex_;

    // Orchestrated components
    FeatureExtractor featureExtractor_;
    ThreatClassifier threatClassifier_;
    RiskScoringEngine riskScoringEngine_;
    AnomalyDetector anomalyDetector_;
    NLPProcessor nlpProcessor_;
    RecommendationEngine recommendationEngine_;
    AutoInvestigation autoInvestigation_;
    PredictionEngine predictionEngine_;
};

} // namespace ThreatOne::AI
