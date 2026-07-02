#include "threat_intel/ThreatIntelEngine.h"
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

namespace ThreatOne::ThreatIntel {

ThreatIntelEngine::ThreatIntelEngine()
    : logger_(Core::Logger::instance().getModuleLogger("ThreatIntel.Engine")) {
}

void ThreatIntelEngine::initialize() {
    if (initialized_) {
        logger_.warn("ThreatIntelEngine already initialized");
        return;
    }

    // Create all components
    iocManager_ = std::make_shared<IOCManager>();
    feedManager_ = std::make_unique<ThreatFeedManager>(iocManager_);
    mitreMatrix_ = std::make_unique<MitreAttackMatrix>();
    cveDatabase_ = std::make_unique<CVEDatabase>();
    correlationEngine_ = std::make_unique<ThreatCorrelationEngine>();
    iocMatcher_ = std::make_unique<IOCMatcher>();
    scoringEngine_ = std::make_unique<ThreatScoringEngine>();
    reportGenerator_ = std::make_unique<IntelReportGenerator>();
    enrichmentService_ = std::make_unique<EnrichmentService>();

    // Set up default correlation rules
    CorrelationRule defaultRule;
    defaultRule.name = "default_correlation";
    defaultRule.timeWindow = std::chrono::seconds(3600);
    defaultRule.minIOCs = 2;
    correlationEngine_->addCorrelationRule(defaultRule);

    // Register local enrichment provider
    auto localProvider = std::make_shared<LocalEnrichmentProvider>(
        *iocManager_, *correlationEngine_, *mitreMatrix_);
    enrichmentService_->registerProvider("local", localProvider);

    initialized_ = true;
    logger_.info("ThreatIntelEngine initialized successfully");
}

ProcessResult ThreatIntelEngine::processIndicator(const std::string& value) {
    ProcessResult result;

    if (!initialized_) {
        logger_.error("Engine not initialized");
        return result;
    }

    // Match indicator against IOC database
    auto matches = iocMatcher_->matchAll(value);
    result.matches = matches;
    result.matched = !matches.empty();

    // Score the best match
    if (!matches.empty()) {
        // Find highest confidence match
        const MatchResult* bestMatch = &matches[0];
        for (const auto& m : matches) {
            if (m.confidence > bestMatch->confidence) {
                bestMatch = &m;
            }
        }

        // Check if this IOC is correlated
        auto allIOCs = iocManager_->getActiveIOCs();
        auto relationships = correlationEngine_->findRelatedIOCs(
            bestMatch->matchedIOC.id, allIOCs);
        bool isCorrelated = !relationships.empty();
        double correlationStrength = 0.0;
        if (isCorrelated) {
            // Average relationship strength
            double totalStrength = 0.0;
            for (const auto& rel : relationships) {
                totalStrength += rel.strength;
            }
            correlationStrength = totalStrength / static_cast<double>(relationships.size());
        }

        result.score = scoringEngine_->calculateScore(
            bestMatch->matchedIOC, isCorrelated, correlationStrength);
    }

    return result;
}

Core::Result<size_t> ThreatIntelEngine::ingestFeed(uint64_t feedId, const std::string& data) {
    if (!initialized_) {
        return Core::Result<size_t>::err(
            Core::Error("Engine not initialized", Core::ErrorCategory::Internal));
    }

    // Record the current size before ingestion so we can identify newly added IOCs
    size_t sizeBefore = iocManager_->size();

    auto result = feedManager_->processFeedData(feedId, data);
    if (result.isOk() && result.value() > 0) {
        // Incrementally add only newly ingested IOCs to the matcher
        auto allIOCs = iocManager_->getActiveIOCs();
        size_t added = 0;
        for (const auto& ioc : allIOCs) {
            if (ioc.id > sizeBefore) {
                iocMatcher_->addIOC(ioc);
                ++added;
            }
        }
        logger_.info("Ingested feed {}, incrementally added {} IOCs to matcher",
                     feedId, added);
    }
    return result;
}

Core::Result<uint64_t> ThreatIntelEngine::addFeed(FeedConfig config) {
    if (!initialized_) {
        return Core::Result<uint64_t>::err(
            Core::Error("Engine not initialized", Core::ErrorCategory::Internal));
    }
    return feedManager_->addFeed(std::move(config));
}

IntelReport ThreatIntelEngine::generateReport() {
    if (!initialized_) {
        logger_.error("Engine not initialized, returning empty report");
        return IntelReport{};
    }
    return reportGenerator_->generateReport(
        *iocManager_, *correlationEngine_, *scoringEngine_);
}

} // namespace ThreatOne::ThreatIntel
