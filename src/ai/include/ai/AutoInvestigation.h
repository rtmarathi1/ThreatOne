#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <mutex>

#include "core/Logger.h"

namespace ThreatOne::AI {

// A piece of evidence collected during investigation
struct Evidence {
    std::string type;
    std::string source;
    std::string data;
    std::string timestamp;
    double relevance = 0.0;
};

// Result of an automated investigation
struct InvestigationResult {
    std::string incidentId;
    std::string scope;
    std::vector<std::string> affectedAssets;
    std::vector<std::string> timeline;
    std::string rootCause;
    std::vector<std::string> suggestedRemediation;
    double confidence = 0.0;
};

// Steps in the investigation workflow
enum class InvestigationStep {
    GatherEvidence,
    CorrelateEvents,
    DetermineScope,
    IdentifyRootCause,
    SuggestRemediation
};

class AutoInvestigation {
public:
    AutoInvestigation();
    ~AutoInvestigation() = default;

    // Run a full automated investigation
    [[nodiscard]] InvestigationResult investigate(
        const std::string& triggerId,
        const std::map<std::string, std::string>& triggerData) const;

    // Gather evidence related to a trigger event
    [[nodiscard]] std::vector<Evidence> gatherEvidence(
        const std::string& triggerId,
        const std::map<std::string, std::string>& triggerData) const;

    // Correlate events by matching common attributes
    [[nodiscard]] std::vector<std::string> correlateEvents(
        const std::vector<Evidence>& evidence) const;

    // Determine scope by counting unique affected assets
    [[nodiscard]] std::vector<std::string> determineScope(
        const std::vector<std::string>& correlations) const;

    // Suggest remediation based on threat type and scope
    [[nodiscard]] std::vector<std::string> suggestRemediation(
        const InvestigationResult& result) const;

private:
    Core::ModuleLogger logger_;

    // Identify root cause from correlation chain
    [[nodiscard]] std::string identifyRootCause(
        const std::vector<Evidence>& evidence,
        const std::vector<std::string>& correlations) const;

    // Build timeline from evidence
    [[nodiscard]] std::vector<std::string> buildTimeline(
        const std::vector<Evidence>& evidence) const;

    // Determine confidence based on evidence quality
    [[nodiscard]] double calculateConfidence(
        const std::vector<Evidence>& evidence,
        const std::vector<std::string>& correlations) const;
};

} // namespace ThreatOne::AI
