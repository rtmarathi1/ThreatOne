#pragma once

// ThreatOne Threat Intel - Threat Intelligence Engine (Facade)
// Owns and coordinates all threat intel components

#include <string>
#include <memory>
#include <vector>
#include <atomic>

#include <core/Error.h>
#include <core/Logger.h>
#include "IOCTypes.h"
#include "IOCManager.h"
#include "ThreatFeedManager.h"
#include "MitreAttack.h"
#include "CVEDatabase.h"
#include "ThreatCorrelation.h"
#include "IOCMatcher.h"
#include "ThreatScoring.h"
#include "IntelReportGenerator.h"
#include "EnrichmentService.h"

namespace ThreatOne::ThreatIntel {

// Result of processing an indicator through the engine
struct ProcessResult {
    bool matched = false;
    std::vector<MatchResult> matches;
    ThreatScore score;
};

// Facade that owns and coordinates all threat intel components
class ThreatIntelEngine {
public:
    ThreatIntelEngine();

    // Initialize all components
    void initialize();

    // Process an observed indicator value (match + score)
    [[nodiscard]] ProcessResult processIndicator(const std::string& value);

    // Ingest feed data by feed ID
    [[nodiscard]] Core::Result<size_t> ingestFeed(uint64_t feedId, const std::string& data);

    // Add a new feed configuration
    [[nodiscard]] Core::Result<uint64_t> addFeed(FeedConfig config);

    // Generate a threat intelligence report
    [[nodiscard]] IntelReport generateReport();

    // Access individual components
    [[nodiscard]] IOCManager& getIOCManager() { return *iocManager_; }
    [[nodiscard]] const IOCManager& getIOCManager() const { return *iocManager_; }
    [[nodiscard]] ThreatFeedManager& getFeedManager() { return *feedManager_; }
    [[nodiscard]] MitreAttackMatrix& getMitreMatrix() { return *mitreMatrix_; }
    [[nodiscard]] CVEDatabase& getCVEDatabase() { return *cveDatabase_; }
    [[nodiscard]] ThreatCorrelationEngine& getCorrelationEngine() { return *correlationEngine_; }
    [[nodiscard]] IOCMatcher& getIOCMatcher() { return *iocMatcher_; }
    [[nodiscard]] ThreatScoringEngine& getScoringEngine() { return *scoringEngine_; }
    [[nodiscard]] IntelReportGenerator& getReportGenerator() { return *reportGenerator_; }
    [[nodiscard]] EnrichmentService& getEnrichmentService() { return *enrichmentService_; }

private:
    std::shared_ptr<IOCManager> iocManager_;
    std::unique_ptr<ThreatFeedManager> feedManager_;
    std::unique_ptr<MitreAttackMatrix> mitreMatrix_;
    std::unique_ptr<CVEDatabase> cveDatabase_;
    std::unique_ptr<ThreatCorrelationEngine> correlationEngine_;
    std::unique_ptr<IOCMatcher> iocMatcher_;
    std::unique_ptr<ThreatScoringEngine> scoringEngine_;
    std::unique_ptr<IntelReportGenerator> reportGenerator_;
    std::unique_ptr<EnrichmentService> enrichmentService_;

    std::atomic<bool> initialized_ = false;
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::ThreatIntel
