#include "ai/AIEngine.h"

#include <sstream>
#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::AI {

AIEngine::AIEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("AIEngine")) {
    logger_.info("AIEngine initialized with all components");
}

ThreatClassification AIEngine::classifyThreat(const std::string& data) {
    logger_.info("classifyThreat called with {} bytes", data.size());

    // Use FeatureExtractor to extract features from the data
    auto fileFeatures = featureExtractor_.extractFileFeatures(data);
    auto featureVector = featureExtractor_.toFeatureVector(fileFeatures);

    // Use ThreatClassifier to classify based on features
    auto classResult = threatClassifier_.classifyFromVector(featureVector);

    ThreatClassification result;
    result.category = ThreatClassifier::categoryToString(classResult.category);
    result.confidence = classResult.confidence;

    // Build description from indicators
    std::string desc = "Classified as " + result.category;
    if (!classResult.indicators.empty()) {
        desc += " based on: ";
        for (size_t i = 0; i < classResult.indicators.size() && i < 3; ++i) {
            if (i > 0) desc += ", ";
            desc += classResult.indicators[i];
        }
    }
    result.description = desc;

    logger_.info("Classification result: {} (confidence: {:.2f})", result.category, result.confidence);
    return result;
}

RiskPrediction AIEngine::predictRisk(const std::string& context) {
    logger_.info("predictRisk called: {}", context);

    // Construct RiskFactors from context string by analyzing keywords.
    // For structured input, use the RiskScoringEngine API directly.

    // Construct RiskFactors from context string
    // The context provides a high-level description; we assign reasonable defaults
    // and adjust based on keywords in the context
    RiskFactors factors;
    factors.fileReputation = 50.0;
    factors.behaviorScore = 50.0;
    factors.networkRisk = 50.0;
    factors.vulnerabilityScore = 50.0;

    // Adjust factors based on context keywords
    if (context.find("malware") != std::string::npos ||
        context.find("malicious") != std::string::npos) {
        factors.fileReputation = 85.0;
        factors.behaviorScore = 75.0;
    }
    if (context.find("network") != std::string::npos ||
        context.find("connection") != std::string::npos) {
        factors.networkRisk = 70.0;
    }
    if (context.find("vulnerability") != std::string::npos ||
        context.find("exploit") != std::string::npos) {
        factors.vulnerabilityScore = 80.0;
    }
    if (context.find("suspicious") != std::string::npos ||
        context.find("anomaly") != std::string::npos) {
        factors.behaviorScore = 65.0;
    }

    // Use RiskScoringEngine for calculation
    auto riskResult = riskScoringEngine_.calculateRisk(factors);

    RiskPrediction prediction;
    prediction.score = riskResult.overallScore;
    prediction.level = riskResult.riskLevel;
    prediction.factors = riskResult.contributingFactors;

    logger_.info("Risk prediction: score={:.1f}, level={}", prediction.score, prediction.level);
    return prediction;
}

PatternAnalysis AIEngine::analyzePattern(const std::string& data) {
    logger_.info("analyzePattern called with {} bytes", data.size());

    // Use AnomalyDetector to analyze patterns in the data
    // Extract features first
    auto fileFeatures = featureExtractor_.extractFileFeatures(data);
    auto featureVector = featureExtractor_.toFeatureVector(fileFeatures);

    // Feed data points to anomaly detector for key features
    for (const auto& [name, value] : featureVector) {
        anomalyDetector_.addDataPoint(name, value);
    }

    // Run isolation forest anomaly detection
    auto anomalyResult = anomalyDetector_.detectIsolationForest(featureVector);

    PatternAnalysis result;
    result.patternId = "PAT-" + std::to_string(
        std::hash<std::string>{}(data.substr(0, std::min(data.size(), size_t{64}))) % 10000);

    if (anomalyResult.isAnomaly) {
        result.description = "Anomalous pattern detected (score: " +
                             std::to_string(anomalyResult.anomalyScore).substr(0, 4) + ")";
        result.confidence = anomalyResult.anomalyScore;
    } else {
        result.description = "Pattern within normal bounds";
        result.confidence = 1.0 - anomalyResult.anomalyScore;
    }

    // Add related indicators from feature analysis
    for (const auto& [name, value] : featureVector) {
        if (value > 0.7) {
            result.relatedIndicators.push_back(name + "=" + std::to_string(value).substr(0, 5));
        }
    }

    return result;
}

IncidentSummary AIEngine::summarizeIncident(const std::string& incidentId) {
    logger_.info("summarizeIncident called: {}", incidentId);

    // Use AutoInvestigation to investigate the incident
    std::map<std::string, std::string> triggerData;
    triggerData["incident_id"] = incidentId;
    triggerData["timestamp"] = "auto-generated";

    auto investigation = autoInvestigation_.investigate(incidentId, triggerData);

    // Use NLPProcessor to generate summary text
    std::vector<std::string> logEntries;
    logEntries.push_back("Incident " + incidentId + " under investigation");
    logEntries.push_back("Scope: " + investigation.scope);
    logEntries.push_back("Root cause: " + investigation.rootCause);
    for (const auto& entry : investigation.timeline) {
        logEntries.push_back(entry);
    }

    auto logSummary = nlpProcessor_.summarizeLog(logEntries);

    IncidentSummary result;
    result.summary = logSummary.summary;
    result.severity = logSummary.severity;
    result.affectedAssets = investigation.affectedAssets;
    result.timeline = investigation.timeline;

    return result;
}

std::vector<Recommendation> AIEngine::getRecommendations(const std::string& context) {
    logger_.info("getRecommendations called: {}", context);

    // Build a RiskPosture from the context by analyzing keywords.
    // For structured input, use the RecommendationEngine API directly.

    // Build a RiskPosture from the context
    RiskPosture posture;
    posture.overallRisk = 50.0;
    posture.openVulnerabilities = 0;
    posture.activeThreats = 0;

    // Parse context for indicators
    if (context.find("threat") != std::string::npos ||
        context.find("attack") != std::string::npos) {
        posture.activeThreats = 3;
        posture.overallRisk = 70.0;
    }
    if (context.find("vulnerability") != std::string::npos ||
        context.find("patch") != std::string::npos) {
        posture.openVulnerabilities = 5;
        posture.overallRisk = std::max(posture.overallRisk, 60.0);
    }
    if (context.find("mfa") != std::string::npos ||
        context.find("authentication") != std::string::npos) {
        posture.configGaps.push_back("mfa_disabled");
    }
    if (context.find("encryption") != std::string::npos) {
        posture.configGaps.push_back("no_encryption");
    }
    if (context.find("port") != std::string::npos ||
        context.find("service") != std::string::npos) {
        posture.configGaps.push_back("open_ports");
    }

    // Use RecommendationEngine to generate recommendations
    auto secRecs = recommendationEngine_.getTopN(5, posture);

    // Convert to IAIEngine::Recommendation format
    std::vector<Recommendation> result;
    result.reserve(secRecs.size());

    for (const auto& rec : secRecs) {
        Recommendation r;
        r.action = rec.title;
        r.priority = (rec.priority <= 2) ? "High" : (rec.priority <= 3) ? "Medium" : "Low";
        r.rationale = rec.description;
        result.push_back(r);
    }

    // If no specific recommendations generated, provide defaults
    if (result.empty()) {
        result.push_back({"Review security posture", "Medium",
                          "Regular security review recommended"});
    }

    return result;
}

} // namespace ThreatOne::AI
