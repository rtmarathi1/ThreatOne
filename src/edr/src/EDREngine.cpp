#include "edr/EDREngine.h"
#include "core/EventBus.h"
#include "core/Event.h"

#include <chrono>
#include <sstream>
#include <iomanip>

namespace ThreatOne::EDR {

namespace {

std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // anonymous namespace

EDREngine::EDREngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("EDREngine")) {
    logger_.info("EDREngine initialized with all components");
}

bool EDREngine::startCollection() {
    if (collecting_.load()) {
        logger_.warn("Collection already started");
        return true;
    }

    logger_.info("Starting EDR collection");

    // Initialize registry monitor with default paths
    registryMonitor_.watchDefaultPaths();

    // Mark as collecting
    collecting_.store(true);

    // Poll monitors once to establish baseline
    processMonitor_.poll();
    fileMonitor_.poll();
    registryMonitor_.poll();

    // Collect initial telemetry
    telemetryCollector_.collectSystemMetrics();

    publishSummaryEvent("EDR collection started", "info");
    logger_.info("EDR collection started successfully");
    return true;
}

bool EDREngine::stopCollection() {
    if (!collecting_.load()) {
        logger_.warn("Collection already stopped");
        return true;
    }

    logger_.info("Stopping EDR collection");
    collecting_.store(false);

    publishSummaryEvent("EDR collection stopped", "info");
    logger_.info("EDR collection stopped");
    return true;
}

std::vector<ProcessInfo> EDREngine::getProcesses() {
    return processMonitor_.enumerateProcesses();
}

std::vector<FileEvent> EDREngine::getFileEvents() {
    // Poll for latest changes
    if (collecting_.load()) {
        fileMonitor_.poll();
    }
    return fileMonitor_.getEvents();
}

std::vector<RegistryEvent> EDREngine::getRegistryEvents() {
    if (collecting_.load()) {
        registryMonitor_.poll();
    }
    return registryMonitor_.getEvents();
}

std::vector<PersistenceIndicator> EDREngine::detectPersistence() {
    auto results = persistenceDetection_.scanForPersistence();
    
    // Feed results into behavior analysis and alert generation
    for (const auto& indicator : results) {
        if (indicator.severity == "high" || indicator.severity == "critical") {
            alertManager_.generateAlert(
                "PersistenceDetection",
                indicator.severity,
                "Persistence mechanism detected: " + indicator.description,
                "Location: " + indicator.location + ", Type: " + indicator.type
            );
        }
    }

    return results;
}

std::vector<LateralMovementIndicator> EDREngine::detectLateralMovement() {
    // Lateral movement detection uses connection events
    // Return indicators from any previously analyzed connections
    return {};
}

std::vector<RansomwareIndicator> EDREngine::detectRansomware() {
    std::vector<RansomwareIndicator> indicators;

    // Get file events and analyze them for ransomware behavior
    auto fileEvents = fileMonitor_.getEvents();
    for (const auto& event : fileEvents) {
        auto result = ransomwareDetection_.analyzeFileOperation(event);
        if (result.has_value()) {
            indicators.push_back(result.value());

            // Generate alert for high-confidence detections
            if (result->confidence == "high") {
                alertManager_.generateAlert(
                    "RansomwareDetection",
                    "critical",
                    "Ransomware activity detected: " + result->indicator,
                    "Affected paths: " + (result->affectedPaths.empty() ? "unknown" : result->affectedPaths[0])
                );
            }
        }
    }

    // Also check behavior analyzer for ransomware patterns
    auto behaviorAlerts = behaviorAnalyzer_.detectRansomwareBehavior();
    for (const auto& alert : behaviorAlerts) {
        RansomwareIndicator ri;
        ri.indicator = "behavior_pattern";
        ri.confidence = alert.severity == "critical" ? "high" : "medium";
        indicators.push_back(ri);
    }

    return indicators;
}

std::vector<EDRAlert> EDREngine::getAlerts() {
    auto alerts = alertManager_.getAlerts();
    std::vector<EDRAlert> result;
    result.reserve(alerts.size());

    for (const auto& alert : alerts) {
        EDRAlert edrAlert;
        edrAlert.id = alert.id;
        edrAlert.source = alert.source;
        edrAlert.severity = alert.severity;
        edrAlert.description = alert.description;
        edrAlert.evidence = alert.evidence;
        edrAlert.timestamp = currentTimestamp();
        result.push_back(std::move(edrAlert));
    }

    return result;
}

std::vector<EDRIncident> EDREngine::getIncidents() {
    auto incidents = incidentTimeline_.getActiveIncidents();
    std::vector<EDRIncident> result;
    result.reserve(incidents.size());

    for (const auto& incident : incidents) {
        EDRIncident edrIncident;
        edrIncident.id = incident.id;
        edrIncident.name = incident.name;
        edrIncident.severity = incident.severity;
        edrIncident.status = incident.status;
        edrIncident.eventCount = incident.events.size();
        result.push_back(std::move(edrIncident));
    }

    return result;
}

std::vector<TimelineEntry> EDREngine::getTimeline(const std::string& incidentId) {
    auto events = incidentTimeline_.getTimeline(incidentId);
    std::vector<TimelineEntry> result;
    result.reserve(events.size());

    for (const auto& event : events) {
        TimelineEntry entry;
        entry.source = event.source;
        entry.type = event.type;
        entry.description = event.description;
        entry.severity = event.severity;
        entry.timestamp = currentTimestamp();
        result.push_back(std::move(entry));
    }

    return result;
}

std::vector<RuleEvaluationResult> EDREngine::evaluateRules(
    const std::string& eventType, const std::string& source,
    const std::string& path, const std::string& details) {

    // Create an EDREvent for rule evaluation
    EDREvent event;
    event.type = eventType;
    event.source = source;
    event.path = path;
    event.details = details;

    // Also feed into behavior analyzer
    behaviorAnalyzer_.addEvent(event);

    // Evaluate against detection rules
    auto matches = rulesEngine_.evaluate(event);

    // Process matches into alerts
    processRuleMatches(matches);

    // Convert to result format
    std::vector<RuleEvaluationResult> results;
    results.reserve(matches.size());

    for (const auto& match : matches) {
        RuleEvaluationResult r;
        r.ruleId = match.ruleId;
        r.ruleName = match.ruleName;
        r.severity = match.severity;
        r.actions = match.actions;
        results.push_back(std::move(r));
    }

    return results;
}

void EDREngine::feedEventsToAnalysis() {
    // Feed file events into behavior analyzer
    auto fileEvents = fileMonitor_.getEvents();
    for (const auto& fe : fileEvents) {
        EDREvent event;
        event.type = "file_" + fe.action;
        event.source = fe.processName;
        event.path = fe.path;
        event.pid = fe.pid;
        behaviorAnalyzer_.addEvent(event);

        // Also evaluate rules
        auto matches = rulesEngine_.evaluate(event);
        processRuleMatches(matches);
    }

    // Check for behavioral patterns
    auto behaviorAlerts = behaviorAnalyzer_.analyzePatterns();
    for (const auto& alert : behaviorAlerts) {
        alertManager_.generateAlert(
            "BehaviorAnalyzer",
            alert.severity,
            alert.description,
            "Pattern: " + alert.patternType
        );
    }
}

void EDREngine::processRuleMatches(const std::vector<RuleMatch>& matches) {
    for (const auto& match : matches) {
        // Generate alert for each rule match
        std::string alertId = alertManager_.generateAlert(
            "DetectionRulesEngine",
            match.severity,
            "Rule matched: " + match.ruleName,
            "Field: " + match.matchedField + ", Value: " + match.matchedValue
        );

        // For high/critical severity, create or update incident
        if (match.severity == "high" || match.severity == "critical") {
            std::string incidentId = incidentTimeline_.createIncident(
                "Rule: " + match.ruleName,
                match.severity
            );

            TimelineEvent te;
            te.source = "DetectionRulesEngine";
            te.type = "rule_match";
            te.description = "Rule matched: " + match.ruleName;
            te.severity = match.severity;
            te.relatedEntities.push_back(match.ruleId);
            incidentTimeline_.addEvent(incidentId, te);
        }
    }
}

void EDREngine::publishSummaryEvent(const std::string& description, const std::string& severity) {
    using namespace ThreatOne::Core;

    SecurityEvent::Severity sev = SecurityEvent::Severity::Info;
    if (severity == "low") sev = SecurityEvent::Severity::Low;
    else if (severity == "medium") sev = SecurityEvent::Severity::Medium;
    else if (severity == "high") sev = SecurityEvent::Severity::High;
    else if (severity == "critical") sev = SecurityEvent::Severity::Critical;

    SecurityEvent event(SecurityEvent::Type::Anomaly, sev, description);
    event.setSource("EDREngine");
    EventBus::instance().publish(event);
}

} // namespace ThreatOne::EDR
