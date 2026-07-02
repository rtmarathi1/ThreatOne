#include "siem/SIEMEngine.h"
#include "core/ServiceLocator.h"

#include <algorithm>
#include <map>

namespace ThreatOne::SIEM {

SIEMEngine::SIEMEngine()
    : startTime_(std::chrono::steady_clock::now())
    , logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SIEMEngine")) {
    // Initialize sub-components
    logStorage_ = std::make_shared<LogStorage>();
    logCollector_ = std::make_shared<LogCollector>();
    logParser_ = std::make_shared<LogParser>();
    eventNormalizer_ = std::make_shared<EventNormalizer>();
    searchEngine_ = std::make_shared<SearchEngine>(logStorage_);
    detectionRules_ = std::make_shared<DetectionRules>();
    sigmaRuleEngine_ = std::make_shared<SigmaRuleEngine>();
    correlationEngine_ = std::make_shared<CorrelationEngine>(logStorage_);
    alertEngine_ = std::make_shared<AlertEngine>();

    // Register key sub-components with ServiceLocator for cross-module access
    auto& locator = Core::ServiceLocator::instance();
    locator.registerService<AlertEngine>(alertEngine_);
    locator.registerService<CorrelationEngine>(correlationEngine_);
    locator.registerService<LogStorage>(logStorage_);
    locator.registerService<LogCollector>(logCollector_);

    logger_.info("SIEMEngine initialized with all sub-components");
}

bool SIEMEngine::ingestLog(const LogEntry& entry) {
    logStorage_->store(entry);
    return true;
}

bool SIEMEngine::ingestBatch(const std::vector<LogEntry>& entries) {
    logStorage_->storeBatch(entries);
    logger_.info("Ingested batch of {} logs", entries.size());
    return true;
}

std::vector<LogEntry> SIEMEngine::searchLogs(const std::string& query) {
    return searchEngine_->textSearch(query);
}

std::vector<LogEntry> SIEMEngine::search(const SearchQuery& query) {
    return searchEngine_->search(query);
}

std::string SIEMEngine::createAlert(const SIEMAlert& alert) {
    return alertEngine_->createAlert(alert);
}

std::vector<SIEMAlert> SIEMEngine::getAlerts() {
    return alertEngine_->getAlerts();
}

std::string SIEMEngine::createRule(const SIEMRule& rule) {
    return detectionRules_->addRule(rule);
}

std::vector<SIEMRule> SIEMEngine::getRules() {
    return detectionRules_->getRules();
}

std::vector<ParsedField> SIEMEngine::parseLog(const std::string& rawLog, LogFormat format) {
    return logParser_->parse(rawLog, format);
}

std::string SIEMEngine::createCorrelationRule(const CorrelationRule& rule) {
    return correlationEngine_->addRule(rule);
}

std::vector<SIEMAlert> SIEMEngine::evaluateRules() {
    auto newAlerts = correlationEngine_->evaluate();

    // Store generated alerts in the alert engine
    for (const auto& alert : newAlerts) {
        alertEngine_->createAlert(alert);
    }

    return newAlerts;
}

DashboardMetrics SIEMEngine::getDashboardMetrics() {
    DashboardMetrics metrics;
    metrics.totalLogs = static_cast<long>(logStorage_->count());

    // Events per second
    auto elapsed = std::chrono::steady_clock::now() - startTime_;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    long totalIngested = logStorage_->getTotalIngested();
    if (seconds > 0) {
        metrics.eventsPerSecond = static_cast<double>(totalIngested) / static_cast<double>(seconds);
    } else {
        metrics.eventsPerSecond = static_cast<double>(totalIngested);
    }

    // Top sources
    auto sourceCounts = logStorage_->getSourceCounts();
    for (const auto& [source, count] : sourceCounts) {
        metrics.topSources.push_back({source, count});
    }

    // Sort by count descending
    std::sort(metrics.topSources.begin(), metrics.topSources.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Keep top 10
    if (metrics.topSources.size() > 10) {
        metrics.topSources.resize(10);
    }

    // Alert rate (alerts per log)
    size_t logCount = logStorage_->count();
    if (logCount > 0) {
        metrics.alertRate = static_cast<double>(alertEngine_->getAlertCount()) /
                           static_cast<double>(logCount);
    }

    // Storage estimate
    metrics.storageUsedBytes = logStorage_->getStorageBytes();

    return metrics;
}

} // namespace ThreatOne::SIEM
