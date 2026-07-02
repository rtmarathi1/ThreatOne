#pragma once

// ThreatOne HIDS - Host-based Intrusion Detection System Implementation
// File integrity, log monitoring, rootkit detection

#include "hids/IHIDSEngine.h"
#include "hids/FileIntegrityMonitor.h"
#include "hids/LogAnalyzer.h"
#include "hids/RootkitDetector.h"
#include "hids/PolicyChecker.h"
#include "hids/SystemCallMonitor.h"
#include "hids/ConfigAuditor.h"
#include "core/Logger.h"

#include <mutex>
#include <memory>
#include <unordered_map>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::HIDS {

class HIDSEngine : public IHIDSEngine {
public:
    HIDSEngine();
    ~HIDSEngine() override = default;

    // Monitoring lifecycle
    bool startMonitoring() override;
    bool stopMonitoring() override;
    [[nodiscard]] MonitoringStatus getMonitoringStatus() override;
    bool setMonitoringConfig(const MonitoringConfig& config) override;

    // File integrity
    std::vector<IntegrityEvent> getIntegrityEvents() override;
    std::vector<FileChange> getFileChanges() override;
    std::vector<PolicyViolation> getPolicyViolations() override;
    BaselineInfo getBaseline() override;
    std::string createBaseline(const std::string& name) override;
    std::vector<IntegrityEvent> compareToBaseline(const std::string& baselineId) override;

    // Monitored path management
    bool addMonitoredPath(const std::string& path) override;
    bool removeMonitoredPath(const std::string& path) override;

    // Log monitoring
    std::string addLogPattern(const LogPattern& pattern) override;
    [[nodiscard]] std::vector<LogPattern> getLogPatterns() override;
    [[nodiscard]] std::vector<SystemLogEntry> getMatchedLogEntries() override;

    // Rootkit detection
    bool runRootkitScan() override;
    [[nodiscard]] std::vector<RootkitIndicator> getRootkitIndicators() override;

    // Non-interface helpers for testing
    void simulateFileChange(const std::string& path, const std::string& newHash);
    void ingestLogEntry(const SystemLogEntry& entry);
    void addPolicyViolation(const PolicyViolation& violation);

    // Access to sub-components
    [[nodiscard]] FileIntegrityMonitor& getFileIntegrityMonitor() { return *fileIntegrityMonitor_; }
    [[nodiscard]] LogAnalyzer& getLogAnalyzer() { return *logAnalyzer_; }
    [[nodiscard]] RootkitDetector& getRootkitDetector() { return *rootkitDetector_; }
    [[nodiscard]] PolicyChecker& getPolicyChecker() { return *policyChecker_; }
    [[nodiscard]] SystemCallMonitor& getSystemCallMonitor() { return *systemCallMonitor_; }
    [[nodiscard]] ConfigAuditor& getConfigAuditor() { return *configAuditor_; }

private:
    std::string generateEventId();
    std::string generateBaselineId();
    std::string generatePatternId();
    std::string generateIndicatorId();
    std::string generateLogEntryId();
    std::string getCurrentTimestamp() const;
    bool matchesPattern(const std::string& text, const std::string& pattern) const;

    mutable std::mutex mutex_;
    MonitoringStatus status_ = MonitoringStatus::Stopped;
    MonitoringConfig config_;
    std::vector<std::string> monitoredPaths_;

    // File integrity
    std::map<std::string, BaselineInfo> baselines_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> baselineHashes_;  // baselineId -> {path -> hash}
    std::unordered_map<std::string, std::string> currentFileHashes_;  // path -> current hash
    std::vector<IntegrityEvent> integrityEvents_;
    std::vector<FileChange> fileChanges_;
    std::vector<PolicyViolation> policyViolations_;

    // Log monitoring
    std::map<std::string, LogPattern> logPatterns_;
    std::vector<SystemLogEntry> logEntries_;

    // Rootkit detection
    std::vector<RootkitIndicator> rootkitIndicators_;

    int nextEventId_ = 1;
    int nextBaselineId_ = 1;
    int nextPatternId_ = 1;
    int nextIndicatorId_ = 1;
    int nextLogEntryId_ = 1;

    // Sub-components
    std::shared_ptr<FileIntegrityMonitor> fileIntegrityMonitor_;
    std::shared_ptr<LogAnalyzer> logAnalyzer_;
    std::shared_ptr<RootkitDetector> rootkitDetector_;
    std::shared_ptr<PolicyChecker> policyChecker_;
    std::shared_ptr<SystemCallMonitor> systemCallMonitor_;
    std::shared_ptr<ConfigAuditor> configAuditor_;

    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::HIDS
