#pragma once

// ThreatOne Threat Intel - Threat Correlation Engine
// Correlates IOCs to identify campaigns and related threats

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>

#include <core/Error.h>
#include <core/Logger.h>
#include "IOCTypes.h"
#include <cstdint>

namespace ThreatOne::ThreatIntel {

// Represents a threat campaign composed of correlated IOCs
struct Campaign {
    std::string id;
    std::string name;
    std::vector<uint64_t> iocIds;
    std::vector<std::string> techniques;    // MITRE ATT&CK technique IDs
    std::vector<std::string> threatActors;
    double confidence = 0.0;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    std::string description;
};

// Rule for correlating IOCs into campaigns
struct CorrelationRule {
    std::string name;
    std::vector<IOCType> iocTypes;          // IOC types to correlate
    std::chrono::seconds timeWindow{3600};  // Time window for correlation
    size_t minIOCs = 2;                     // Minimum IOCs needed to trigger
};

// Describes a relationship between IOCs
struct IOCRelationship {
    uint64_t relatedIOCId;
    std::string relationshipType;  // e.g., "same_source", "same_campaign", "temporal"
    double strength = 0.0;         // 0.0 - 1.0
};

// Engine that correlates multiple IOCs to identify campaigns
class ThreatCorrelationEngine {
public:
    ThreatCorrelationEngine();

    // Add a correlation rule
    void addCorrelationRule(const CorrelationRule& rule);

    // Correlate a set of IOCs against all rules, return identified campaigns
    [[nodiscard]] std::vector<Campaign> correlateIOCs(const std::vector<IOC>& iocs) const;

    // Find IOCs related to a given IOC ID
    [[nodiscard]] std::vector<IOCRelationship> findRelatedIOCs(
        uint64_t iocId, const std::vector<IOC>& allIOCs) const;

    // Calculate a correlation score for a campaign (0.0 - 1.0)
    [[nodiscard]] double calculateCorrelationScore(const Campaign& campaign) const;

    // Get all registered rules
    [[nodiscard]] std::vector<CorrelationRule> getRules() const;

    // Get rule count
    [[nodiscard]] size_t ruleCount() const;

private:
    mutable std::shared_mutex mutex_;
    std::vector<CorrelationRule> rules_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::ThreatIntel
