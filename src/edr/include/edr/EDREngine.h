#pragma once

#include "edr/IEDREngine.h"
#include "edr/ProcessMonitor.h"
#include "edr/FileMonitor.h"
#include "edr/RegistryMonitor.h"
#include "edr/MemoryMonitor.h"
#include "edr/TelemetryCollector.h"
#include "edr/BehaviorAnalyzer.h"
#include "edr/DetectionRulesEngine.h"
#include "edr/AlertManager.h"
#include "edr/PersistenceDetection.h"
#include "edr/RansomwareDetection.h"
#include "edr/LateralMovementDetection.h"
#include "edr/IncidentTimeline.h"
#include "core/Logger.h"

#include <atomic>
#include <memory>

namespace ThreatOne::EDR {

class EDREngine : public IEDREngine {
public:
    EDREngine();
    ~EDREngine() override = default;

    // Lifecycle
    bool startCollection() override;
    bool stopCollection() override;

    // Process monitoring
    std::vector<ProcessInfo> getProcesses() override;

    // File monitoring
    std::vector<FileEvent> getFileEvents() override;

    // Registry/config monitoring
    std::vector<RegistryEvent> getRegistryEvents() override;

    // Detection capabilities
    std::vector<PersistenceIndicator> detectPersistence() override;
    std::vector<LateralMovementIndicator> detectLateralMovement() override;
    std::vector<RansomwareIndicator> detectRansomware() override;

    // Alert management
    std::vector<EDRAlert> getAlerts() override;

    // Incident management
    std::vector<EDRIncident> getIncidents() override;
    std::vector<TimelineEntry> getTimeline(const std::string& incidentId) override;

    // Rule evaluation
    std::vector<RuleEvaluationResult> evaluateRules(
        const std::string& eventType, const std::string& source,
        const std::string& path, const std::string& details) override;

    // Component accessors for MonitorEngine integration
    ProcessMonitor& getProcessMonitor() { return processMonitor_; }
    FileMonitor& getFileMonitor() { return fileMonitor_; }
    TelemetryCollector& getTelemetryCollector() { return telemetryCollector_; }
    BehaviorAnalyzer& getBehaviorAnalyzer() { return behaviorAnalyzer_; }
    AlertManager& getAlertManager() { return alertManager_; }

private:
    void feedEventsToAnalysis();
    void processRuleMatches(const std::vector<RuleMatch>& matches);
    void publishSummaryEvent(const std::string& description, const std::string& severity);

    ThreatOne::Core::ModuleLogger logger_;
    std::atomic<bool> collecting_{false};

    // Core monitoring components
    ProcessMonitor processMonitor_;
    FileMonitor fileMonitor_;
    RegistryMonitor registryMonitor_;
    MemoryMonitor memoryMonitor_;

    // Telemetry and analysis
    TelemetryCollector telemetryCollector_;
    BehaviorAnalyzer behaviorAnalyzer_;
    DetectionRulesEngine rulesEngine_;

    // Alert and incident management
    AlertManager alertManager_;
    PersistenceDetection persistenceDetection_;
    RansomwareDetection ransomwareDetection_;
    LateralMovementDetection lateralMovementDetection_;
    IncidentTimeline incidentTimeline_;
};

} // namespace ThreatOne::EDR
