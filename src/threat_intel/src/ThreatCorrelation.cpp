#include "threat_intel/ThreatCorrelation.h"

#include <algorithm>
#include <sstream>
#include <cmath>

namespace ThreatOne::ThreatIntel {

ThreatCorrelationEngine::ThreatCorrelationEngine()
    : logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.Correlation")) {
}

void ThreatCorrelationEngine::addCorrelationRule(const CorrelationRule& rule) {
    std::unique_lock lock(mutex_);
    rules_.push_back(rule);
    logger_.debug("Added correlation rule: {}", rule.name);
}

std::vector<Campaign> ThreatCorrelationEngine::correlateIOCs(const std::vector<IOC>& iocs) const {
    std::shared_lock lock(mutex_);

    std::vector<Campaign> campaigns;

    for (const auto& rule : rules_) {
        // Group IOCs by source within the time window and matching the required types
        std::unordered_map<std::string, std::vector<const IOC*>> sourceGroups;

        for (const auto& ioc : iocs) {
            // Check if this IOC matches one of the required types
            bool typeMatch = rule.iocTypes.empty(); // Empty means match all
            for (const auto& requiredType : rule.iocTypes) {
                if (ioc.type == requiredType) {
                    typeMatch = true;
                    break;
                }
            }
            if (!typeMatch) continue;

            sourceGroups[ioc.source].push_back(&ioc);
        }

        // Check each source group for time-window correlation
        for (const auto& [source, group] : sourceGroups) {
            if (group.size() < rule.minIOCs) continue;

            // Find IOCs within the time window
            for (size_t i = 0; i < group.size(); ++i) {
                std::vector<const IOC*> correlated;
                correlated.push_back(group[i]);

                for (size_t j = i + 1; j < group.size(); ++j) {
                    auto timeDiff = std::chrono::duration_cast<std::chrono::seconds>(
                        group[j]->firstSeen > group[i]->firstSeen
                            ? group[j]->firstSeen - group[i]->firstSeen
                            : group[i]->firstSeen - group[j]->firstSeen);

                    if (timeDiff <= rule.timeWindow) {
                        correlated.push_back(group[j]);
                    }
                }

                if (correlated.size() >= rule.minIOCs) {
                    Campaign campaign;
                    campaign.id = rule.name + "_" + source + "_" + std::to_string(i);
                    campaign.name = rule.name + " - " + source;
                    campaign.description = "Auto-correlated campaign from rule: " + rule.name;

                    auto earliest = std::chrono::system_clock::time_point::max();
                    auto latest = std::chrono::system_clock::time_point::min();

                    double totalConfidence = 0.0;
                    for (const auto* ioc : correlated) {
                        campaign.iocIds.push_back(ioc->id);
                        totalConfidence += ioc->confidence;
                        if (ioc->firstSeen < earliest) earliest = ioc->firstSeen;
                        if (ioc->lastSeen > latest) latest = ioc->lastSeen;
                    }

                    campaign.firstSeen = earliest;
                    campaign.lastSeen = latest;
                    campaign.confidence = totalConfidence / static_cast<double>(correlated.size());
                    campaign.threatActors.push_back(source);

                    campaigns.push_back(std::move(campaign));
                    break; // One campaign per source group per rule
                }
            }
        }
    }

    return campaigns;
}

std::vector<IOCRelationship> ThreatCorrelationEngine::findRelatedIOCs(
    uint64_t iocId, const std::vector<IOC>& allIOCs) const {
    std::shared_lock lock(mutex_);

    std::vector<IOCRelationship> relationships;

    // Find the target IOC
    const IOC* target = nullptr;
    for (const auto& ioc : allIOCs) {
        if (ioc.id == iocId) {
            target = &ioc;
            break;
        }
    }
    if (!target) return relationships;

    for (const auto& ioc : allIOCs) {
        if (ioc.id == iocId) continue;

        // Same source relationship
        if (ioc.source == target->source) {
            IOCRelationship rel;
            rel.relatedIOCId = ioc.id;
            rel.relationshipType = "same_source";
            rel.strength = 0.6;
            relationships.push_back(rel);
            continue;
        }

        // Temporal relationship (seen within 1 hour of each other)
        auto timeDiff = std::chrono::duration_cast<std::chrono::hours>(
            ioc.firstSeen > target->firstSeen
                ? ioc.firstSeen - target->firstSeen
                : target->firstSeen - ioc.firstSeen);

        if (timeDiff <= std::chrono::hours(1)) {
            IOCRelationship rel;
            rel.relatedIOCId = ioc.id;
            rel.relationshipType = "temporal";
            // Closer in time = stronger relationship
            double hoursDiff = static_cast<double>(timeDiff.count());
            rel.strength = 1.0 - (hoursDiff / 1.0); // Max 1 hour window
            if (rel.strength < 0.1) rel.strength = 0.1;
            relationships.push_back(rel);
            continue;
        }

        // Same type and similar tags
        if (ioc.type == target->type && !ioc.tags.empty() && !target->tags.empty()) {
            for (const auto& tag : ioc.tags) {
                for (const auto& targetTag : target->tags) {
                    if (tag == targetTag) {
                        IOCRelationship rel;
                        rel.relatedIOCId = ioc.id;
                        rel.relationshipType = "same_campaign";
                        rel.strength = 0.7;
                        relationships.push_back(rel);
                        goto nextIOC;
                    }
                }
            }
        }
        nextIOC:;
    }

    return relationships;
}

double ThreatCorrelationEngine::calculateCorrelationScore(const Campaign& campaign) const {
    // Score factors:
    // 1. Number of IOCs (more = stronger correlation)
    // 2. Average confidence of IOCs
    // 3. Time span (tighter timeframe = stronger)
    // 4. Diversity of IOC types

    double score = 0.0;

    // IOC count factor (diminishing returns after 10)
    double countFactor = std::min(1.0, static_cast<double>(campaign.iocIds.size()) / 10.0);
    score += countFactor * 0.3;

    // Confidence factor
    score += campaign.confidence * 0.3;

    // Time span factor (shorter is better, max 1.0 if within 1 hour)
    if (campaign.firstSeen != std::chrono::system_clock::time_point{} &&
        campaign.lastSeen != std::chrono::system_clock::time_point{}) {
        auto duration = std::chrono::duration_cast<std::chrono::hours>(
            campaign.lastSeen - campaign.firstSeen);
        double hours = static_cast<double>(duration.count());
        double timeFactor = std::exp(-hours / 24.0); // Decay over 24 hours
        score += timeFactor * 0.2;
    } else {
        score += 0.1; // Default if no time info
    }

    // Technique diversity
    double techFactor = std::min(1.0, static_cast<double>(campaign.techniques.size()) / 5.0);
    score += techFactor * 0.2;

    return std::min(1.0, std::max(0.0, score));
}

std::vector<CorrelationRule> ThreatCorrelationEngine::getRules() const {
    std::shared_lock lock(mutex_);
    return rules_;
}

size_t ThreatCorrelationEngine::ruleCount() const {
    std::shared_lock lock(mutex_);
    return rules_.size();
}

} // namespace ThreatOne::ThreatIntel
