#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::EDR {

struct ProcessInfo {
    uint64_t pid = 0;
    std::string name;
    std::string path;
    std::string user;
    uint64_t parentPid = 0;
    std::string commandLine;
    double cpuUsage = 0.0;
    uint64_t memoryBytes = 0;
};

struct FileEvent {
    std::string path;
    std::string action;  // "created", "modified", "deleted", "renamed"
    std::string processName;
    uint64_t pid = 0;
    std::string timestamp;
    uint64_t fileSize = 0;
};

struct RegistryEvent {
    std::string key;
    std::string action;  // "created", "modified", "deleted"
    std::string value;
    std::string processName;
    std::string timestamp;
};

struct PersistenceIndicator {
    std::string type;        // "cron", "systemd", "shell_profile", "ld_preload", etc.
    std::string location;
    std::string description;
    std::string severity;    // "low", "medium", "high", "critical"
};

struct LateralMovementIndicator {
    std::string sourceHost;
    std::string destHost;
    std::string technique;   // "ssh_brute_force", "credential_access", "remote_exec"
    std::string timestamp;
    std::string severity;
};

struct RansomwareIndicator {
    std::string indicator;    // "high_entropy", "known_extension", "mass_rename", "ransom_note"
    std::string confidence;   // "low", "medium", "high"
    std::vector<std::string> affectedPaths;
};

struct EDRAlert {
    std::string id;
    std::string source;
    std::string severity;
    std::string description;
    std::string evidence;
    std::string timestamp;
};

struct EDRIncident {
    std::string id;
    std::string name;
    std::string severity;
    std::string status;
    size_t eventCount = 0;
};

struct TimelineEntry {
    std::string source;
    std::string type;
    std::string description;
    std::string severity;
    std::string timestamp;
};

struct RuleEvaluationResult {
    std::string ruleId;
    std::string ruleName;
    std::string severity;
    std::vector<std::string> actions;
};

class IEDREngine {
public:
    virtual ~IEDREngine() = default;

    // Lifecycle
    virtual bool startCollection() = 0;
    virtual bool stopCollection() = 0;

    // Process monitoring
    virtual std::vector<ProcessInfo> getProcesses() = 0;

    // File monitoring
    virtual std::vector<FileEvent> getFileEvents() = 0;

    // Registry/config monitoring
    virtual std::vector<RegistryEvent> getRegistryEvents() = 0;

    // Detection capabilities
    virtual std::vector<PersistenceIndicator> detectPersistence() = 0;
    virtual std::vector<LateralMovementIndicator> detectLateralMovement() = 0;
    virtual std::vector<RansomwareIndicator> detectRansomware() = 0;

    // Alert management
    virtual std::vector<EDRAlert> getAlerts() = 0;

    // Incident management
    virtual std::vector<EDRIncident> getIncidents() = 0;
    virtual std::vector<TimelineEntry> getTimeline(const std::string& incidentId) = 0;

    // Rule evaluation
    virtual std::vector<RuleEvaluationResult> evaluateRules(
        const std::string& eventType, const std::string& source,
        const std::string& path, const std::string& details) = 0;
};

} // namespace ThreatOne::EDR
