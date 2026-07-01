#include "ai/PredictionEngine.h"

#include <algorithm>
#include <numeric>
#include <cmath>
#include <map>

namespace ThreatOne::AI {

PredictionEngine::PredictionEngine()
    : logger_(Core::Logger::instance().getModuleLogger("PredictionEngine")) {
    logger_.info("PredictionEngine initialized");
}

PredictionResult PredictionEngine::predictAttackLikelihood(
    const ThreatIntelligence& intel,
    const std::vector<std::string>& vulnerabilities,
    const std::vector<double>& history) const {

    logger_.debug("Predicting attack likelihood: {} campaigns, {} vulns, {} history points",
                  intel.activeCampaigns.size(), vulnerabilities.size(), history.size());

    PredictionResult result;

    // Component 1: Vulnerability exposure score (weight: 0.35)
    double vulnScore = computeVulnerabilityScore(vulnerabilities);

    // Component 2: Historical attack frequency (weight: 0.30)
    double histScore = computeHistoricalFrequency(history);

    // Component 3: Threat intel correlation (weight: 0.35)
    double intelScore = computeIntelCorrelation(intel, vulnerabilities);

    // Weighted combination
    result.likelihood = clamp01(0.35 * vulnScore + 0.30 * histScore + 0.35 * intelScore);

    // Determine confidence based on data quality
    double dataPoints = static_cast<double>(vulnerabilities.size() + history.size() +
                        intel.activeCampaigns.size());
    result.confidence = clamp01(std::min(1.0, dataPoints / 20.0));

    // Determine timeframe based on trend
    if (!history.empty()) {
        auto trend = getHistoricalTrend(history);
        if (!trend.empty() && trend.back() > trend.front()) {
            result.timeframe = "24-48 hours";
        } else {
            result.timeframe = "1-2 weeks";
        }
    } else {
        result.timeframe = "unknown";
    }

    // Determine predicted threat type
    result.predictedThreatType = determineThreatType(intel);

    // Build reasoning
    if (vulnScore > 0.5) {
        result.reasoning.push_back("High vulnerability exposure (score: " +
                                    std::to_string(vulnScore).substr(0, 4) + ")");
    }
    if (histScore > 0.5) {
        result.reasoning.push_back("Elevated historical attack frequency");
    }
    if (intelScore > 0.5) {
        result.reasoning.push_back("Active threat campaigns correlate with known vulnerabilities");
    }
    if (!intel.industryTargeting.empty()) {
        result.reasoning.push_back("Industry targeting detected in " +
                                    std::to_string(intel.industryTargeting.size()) + " campaigns");
    }
    if (result.reasoning.empty()) {
        result.reasoning.push_back("Low overall threat indicators");
    }

    logger_.info("Prediction: likelihood={:.3f}, confidence={:.3f}, timeframe={}",
                 result.likelihood, result.confidence, result.timeframe);

    return result;
}

std::string PredictionEngine::predictNextTarget(
    const std::vector<std::string>& history) const {

    if (history.empty()) {
        return "unknown";
    }

    // Simple frequency analysis - most targeted entity is likely next target
    std::map<std::string, int> targetCounts;
    for (const auto& target : history) {
        targetCounts[target]++;
    }

    std::string mostFrequent = history.back();
    int maxCount = 0;
    for (const auto& [target, count] : targetCounts) {
        if (count > maxCount) {
            maxCount = count;
            mostFrequent = target;
        }
    }

    // Recency bias: if the most recent targets differ from the most frequent,
    // give weight to recent targets
    if (history.size() >= 3) {
        std::map<std::string, int> recentCounts;
        for (size_t i = history.size() - 3; i < history.size(); ++i) {
            recentCounts[history[i]]++;
        }
        for (const auto& [target, count] : recentCounts) {
            if (count >= 2) {
                return target;  // Strong recent signal
            }
        }
    }

    return mostFrequent;
}

double PredictionEngine::assessExposure(
    const std::vector<std::string>& vulnerabilities) const {

    return computeVulnerabilityScore(vulnerabilities);
}

std::vector<double> PredictionEngine::getHistoricalTrend(
    const std::vector<double>& eventCounts) const {

    if (eventCounts.size() < 2) {
        return eventCounts;
    }

    // Apply simple linear regression to produce trend line
    auto [slope, intercept] = linearRegression(eventCounts);

    std::vector<double> trendLine;
    trendLine.reserve(eventCounts.size());

    for (size_t i = 0; i < eventCounts.size(); ++i) {
        double x = static_cast<double>(i);
        trendLine.push_back(slope * x + intercept);
    }

    return trendLine;
}

double PredictionEngine::computeVulnerabilityScore(
    const std::vector<std::string>& vulnerabilities) const {

    if (vulnerabilities.empty()) return 0.0;

    // Assign severity weights based on naming conventions
    double weightedCount = 0.0;
    for (const auto& vuln : vulnerabilities) {
        // Simple heuristic: "critical" vulns get weight 1.0, "high" 0.7, etc.
        if (vuln.find("critical") != std::string::npos ||
            vuln.find("CRITICAL") != std::string::npos) {
            weightedCount += 1.0;
        } else if (vuln.find("high") != std::string::npos ||
                   vuln.find("HIGH") != std::string::npos) {
            weightedCount += 0.7;
        } else if (vuln.find("medium") != std::string::npos ||
                   vuln.find("MEDIUM") != std::string::npos) {
            weightedCount += 0.4;
        } else {
            weightedCount += 0.5;  // Default weight
        }
    }

    // Normalize: saturates around 10 weighted vulnerabilities
    return clamp01(1.0 - std::exp(-weightedCount / 5.0));
}

double PredictionEngine::computeHistoricalFrequency(
    const std::vector<double>& history) const {

    if (history.empty()) return 0.0;

    // Compute average event count
    double sum = std::accumulate(history.begin(), history.end(), 0.0);
    double avg = sum / static_cast<double>(history.size());

    // Check recent trend (last 3 values vs overall average)
    double recentAvg = avg;
    if (history.size() >= 3) {
        double recentSum = 0.0;
        for (size_t i = history.size() - 3; i < history.size(); ++i) {
            recentSum += history[i];
        }
        recentAvg = recentSum / 3.0;
    }

    // If recent is above average, frequency is increasing
    double trendFactor = (avg > 0.0) ? (recentAvg / avg) : 1.0;

    // Normalize: assume more than 10 events per period is high
    double baseScore = clamp01(avg / 10.0);

    // Apply trend multiplier
    return clamp01(baseScore * std::min(2.0, trendFactor));
}

double PredictionEngine::computeIntelCorrelation(
    const ThreatIntelligence& intel,
    const std::vector<std::string>& vulnerabilities) const {

    if (intel.activeCampaigns.empty()) return 0.0;

    double score = 0.0;

    // Active campaigns increase base score
    score += std::min(0.4, static_cast<double>(intel.activeCampaigns.size()) * 0.1);

    // Industry targeting increases score
    if (!intel.industryTargeting.empty()) {
        score += 0.2;
    }

    // Correlation between known vulns in intel and actual vulnerabilities
    if (!intel.knownVulnerabilities.empty() && !vulnerabilities.empty()) {
        int matches = 0;
        for (const auto& knownVuln : intel.knownVulnerabilities) {
            for (const auto& vuln : vulnerabilities) {
                if (vuln.find(knownVuln) != std::string::npos ||
                    knownVuln.find(vuln) != std::string::npos) {
                    matches++;
                }
            }
        }
        if (matches > 0) {
            score += std::min(0.4, static_cast<double>(matches) * 0.15);
        }
    }

    return clamp01(score);
}

std::pair<double, double> PredictionEngine::linearRegression(
    const std::vector<double>& values) const {

    if (values.empty()) return {0.0, 0.0};
    if (values.size() == 1) return {0.0, values[0]};

    double n = static_cast<double>(values.size());
    double sumX = 0.0, sumY = 0.0, sumXY = 0.0, sumXX = 0.0;

    for (size_t i = 0; i < values.size(); ++i) {
        double x = static_cast<double>(i);
        double y = values[i];
        sumX += x;
        sumY += y;
        sumXY += x * y;
        sumXX += x * x;
    }

    double denom = n * sumXX - sumX * sumX;
    if (std::abs(denom) < 1e-10) {
        return {0.0, sumY / n};
    }

    double slope = (n * sumXY - sumX * sumY) / denom;
    double intercept = (sumY - slope * sumX) / n;

    return {slope, intercept};
}

std::string PredictionEngine::determineThreatType(
    const ThreatIntelligence& intel) const {

    if (intel.activeCampaigns.empty()) {
        return "unknown";
    }

    // Analyze campaign names for threat type keywords
    for (const auto& campaign : intel.activeCampaigns) {
        if (campaign.find("ransomware") != std::string::npos ||
            campaign.find("ransom") != std::string::npos) {
            return "ransomware";
        }
        if (campaign.find("apt") != std::string::npos ||
            campaign.find("APT") != std::string::npos) {
            return "advanced_persistent_threat";
        }
        if (campaign.find("phishing") != std::string::npos) {
            return "phishing";
        }
        if (campaign.find("ddos") != std::string::npos ||
            campaign.find("DDoS") != std::string::npos) {
            return "denial_of_service";
        }
        if (campaign.find("exploit") != std::string::npos) {
            return "exploit";
        }
    }

    return "targeted_attack";
}

double PredictionEngine::clamp01(double value) {
    return std::min(1.0, std::max(0.0, value));
}

} // namespace ThreatOne::AI
