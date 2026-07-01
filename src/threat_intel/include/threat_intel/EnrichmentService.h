#pragma once

// ThreatOne Threat Intel - Enrichment Service
// Enriches IOCs with additional context from local and external sources

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

#include <core/Error.h>
#include <core/Logger.h>
#include "IOCTypes.h"
#include "IOCManager.h"
#include "ThreatCorrelation.h"
#include "MitreAttack.h"

namespace ThreatOne::ThreatIntel {

// Result of enriching an IOC
struct EnrichmentResult {
    IOC originalIOC;
    std::vector<IOC> relatedIOCs;
    std::vector<std::string> campaigns;
    std::vector<std::string> threatActors;
    std::vector<std::string> ttps;  // MITRE technique IDs
    std::unordered_map<std::string, std::string> additionalContext;
};

// Interface for enrichment providers
class IEnrichmentProvider {
public:
    virtual ~IEnrichmentProvider() = default;

    // Enrich a single IOC with additional context
    [[nodiscard]] virtual EnrichmentResult enrich(const IOC& ioc) = 0;
};

// Local enrichment using IOCManager, CorrelationEngine, and MITRE data
class LocalEnrichmentProvider : public IEnrichmentProvider {
public:
    LocalEnrichmentProvider(const IOCManager& iocManager,
                            const ThreatCorrelationEngine& correlationEngine,
                            const MitreAttackMatrix& mitreMatrix);

    [[nodiscard]] EnrichmentResult enrich(const IOC& ioc) override;

private:
    const IOCManager& iocManager_;
    const ThreatCorrelationEngine& correlationEngine_;
    const MitreAttackMatrix& mitreMatrix_;
};

// Stub external enrichment provider (VirusTotal/AbuseIPDB/AlienVault OTX)
// Returns empty results since no network access is available
class ExternalEnrichmentProvider : public IEnrichmentProvider {
public:
    explicit ExternalEnrichmentProvider(const std::string& providerName,
                                         const std::string& apiKey = "");

    [[nodiscard]] EnrichmentResult enrich(const IOC& ioc) override;

    [[nodiscard]] const std::string& providerName() const { return providerName_; }

private:
    std::string providerName_;
    std::string apiKey_;
};

// Service that coordinates multiple enrichment providers
class EnrichmentService {
public:
    EnrichmentService();

    // Register a named enrichment provider
    void registerProvider(const std::string& name, std::shared_ptr<IEnrichmentProvider> provider);

    // Enrich a single IOC using all registered providers
    [[nodiscard]] EnrichmentResult enrich(const IOC& ioc);

    // Enrich a batch of IOCs
    [[nodiscard]] std::vector<EnrichmentResult> enrichBatch(const std::vector<IOC>& iocs);

    // Get the number of registered providers
    [[nodiscard]] size_t providerCount() const;

    // Get provider names
    [[nodiscard]] std::vector<std::string> getProviderNames() const;

private:
    std::unordered_map<std::string, std::shared_ptr<IEnrichmentProvider>> providers_;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::ThreatIntel
