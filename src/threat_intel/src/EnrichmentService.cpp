#include "threat_intel/EnrichmentService.h"

#include <algorithm>

namespace ThreatOne::ThreatIntel {

// --- LocalEnrichmentProvider ---

LocalEnrichmentProvider::LocalEnrichmentProvider(
    const IOCManager& iocManager,
    const ThreatCorrelationEngine& correlationEngine,
    const MitreAttackMatrix& mitreMatrix)
    : iocManager_(iocManager)
    , correlationEngine_(correlationEngine)
    , mitreMatrix_(mitreMatrix) {
}

EnrichmentResult LocalEnrichmentProvider::enrich(const IOC& ioc) {
    EnrichmentResult result;
    result.originalIOC = ioc;

    // Find related IOCs through correlation
    auto allIOCs = iocManager_.getActiveIOCs();
    auto relationships = correlationEngine_.findRelatedIOCs(ioc.id, allIOCs);

    for (const auto& rel : relationships) {
        auto relatedResult = iocManager_.getIOCById(rel.relatedIOCId);
        if (relatedResult.isOk()) {
            result.relatedIOCs.push_back(relatedResult.value());
        }
    }

    // Correlate to identify campaigns
    auto campaigns = correlationEngine_.correlateIOCs(allIOCs);
    for (const auto& campaign : campaigns) {
        for (uint64_t campaignIOCId : campaign.iocIds) {
            if (campaignIOCId == ioc.id) {
                result.campaigns.push_back(campaign.name);
                for (const auto& actor : campaign.threatActors) {
                    if (std::find(result.threatActors.begin(), result.threatActors.end(), actor)
                        == result.threatActors.end()) {
                        result.threatActors.push_back(actor);
                    }
                }
                for (const auto& tech : campaign.techniques) {
                    if (std::find(result.ttps.begin(), result.ttps.end(), tech)
                        == result.ttps.end()) {
                        result.ttps.push_back(tech);
                    }
                }
                break;
            }
        }
    }

    // Try to map to MITRE techniques based on IOC type and tags
    std::string searchTerm;
    switch (ioc.type) {
        case IOCType::IP:
        case IOCType::Domain:
        case IOCType::URL:
            searchTerm = "protocol";  // matches "Application Layer Protocol"
            break;
        case IOCType::Hash_MD5:
        case IOCType::Hash_SHA1:
        case IOCType::Hash_SHA256:
        case IOCType::FilePath:
            searchTerm = "obfuscated";  // matches "Obfuscated Files or Information"
            break;
        case IOCType::EmailAddress:
            searchTerm = "phishing";  // matches "Phishing"
            break;
    }

    if (!searchTerm.empty()) {
        auto techniques = mitreMatrix_.searchTechniques(searchTerm);
        for (const auto& tech : techniques) {
            if (std::find(result.ttps.begin(), result.ttps.end(), tech.id) == result.ttps.end()) {
                result.ttps.push_back(tech.id);
                if (result.ttps.size() >= 3) break; // Limit to top 3 matches
            }
        }
    }

    // Add context
    result.additionalContext["source"] = ioc.source;
    result.additionalContext["related_count"] = std::to_string(result.relatedIOCs.size());
    result.additionalContext["campaign_count"] = std::to_string(result.campaigns.size());
    result.additionalContext["enrichment_provider"] = "local";

    return result;
}

// --- ExternalEnrichmentProvider ---

ExternalEnrichmentProvider::ExternalEnrichmentProvider(
    const std::string& providerName, const std::string& apiKey)
    : providerName_(providerName)
    , apiKey_(apiKey) {
}

EnrichmentResult ExternalEnrichmentProvider::enrich(const IOC& ioc) {
    // Stub implementation - no network access available
    EnrichmentResult result;
    result.originalIOC = ioc;
    result.additionalContext["enrichment_provider"] = providerName_;
    result.additionalContext["status"] = "unavailable";
    result.additionalContext["reason"] = "No network access for external API calls";
    return result;
}

// --- EnrichmentService ---

EnrichmentService::EnrichmentService()
    : logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.EnrichmentService")) {
}

void EnrichmentService::registerProvider(
    const std::string& name, std::shared_ptr<IEnrichmentProvider> provider) {
    providers_[name] = std::move(provider);
    logger_.info("Registered enrichment provider: {}", name);
}

EnrichmentResult EnrichmentService::enrich(const IOC& ioc) {
    EnrichmentResult combinedResult;
    combinedResult.originalIOC = ioc;

    for (const auto& [name, provider] : providers_) {
        auto providerResult = provider->enrich(ioc);

        // Merge related IOCs
        for (const auto& related : providerResult.relatedIOCs) {
            combinedResult.relatedIOCs.push_back(related);
        }

        // Merge campaigns
        for (const auto& campaign : providerResult.campaigns) {
            if (std::find(combinedResult.campaigns.begin(),
                          combinedResult.campaigns.end(), campaign)
                == combinedResult.campaigns.end()) {
                combinedResult.campaigns.push_back(campaign);
            }
        }

        // Merge threat actors
        for (const auto& actor : providerResult.threatActors) {
            if (std::find(combinedResult.threatActors.begin(),
                          combinedResult.threatActors.end(), actor)
                == combinedResult.threatActors.end()) {
                combinedResult.threatActors.push_back(actor);
            }
        }

        // Merge TTPs
        for (const auto& ttp : providerResult.ttps) {
            if (std::find(combinedResult.ttps.begin(),
                          combinedResult.ttps.end(), ttp)
                == combinedResult.ttps.end()) {
                combinedResult.ttps.push_back(ttp);
            }
        }

        // Merge context (prefix with provider name to avoid collisions)
        for (const auto& [key, value] : providerResult.additionalContext) {
            combinedResult.additionalContext[name + "." + key] = value;
        }
    }

    logger_.debug("Enriched IOC {} with {} providers", ioc.value, providers_.size());
    return combinedResult;
}

std::vector<EnrichmentResult> EnrichmentService::enrichBatch(const std::vector<IOC>& iocs) {
    std::vector<EnrichmentResult> results;
    results.reserve(iocs.size());

    for (const auto& ioc : iocs) {
        results.push_back(enrich(ioc));
    }

    logger_.info("Batch enriched {} IOCs", iocs.size());
    return results;
}

size_t EnrichmentService::providerCount() const {
    return providers_.size();
}

std::vector<std::string> EnrichmentService::getProviderNames() const {
    std::vector<std::string> names;
    names.reserve(providers_.size());
    for (const auto& [name, provider] : providers_) {
        names.push_back(name);
    }
    return names;
}

} // namespace ThreatOne::ThreatIntel
