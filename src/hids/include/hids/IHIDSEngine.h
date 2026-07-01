#pragma once

// ThreatOne HIDS - Host-based Intrusion Detection System Interface
// File integrity monitoring, log monitoring, rootkit detection

#include <string>
#include <vector>

namespace ThreatOne::HIDS {

struct IntegrityEvent {
    std::string id;
    std::string path;
    std::string changeType;
    std::string previousHash;
    std::string currentHash;
    std::string timestamp;
};

struct FileChange {
    std::string path;
    std::string action;
    std::string user;
    uint64_t size = 0;
    std::string timestamp;
};

struct PolicyViolation {
    std::string id;
    std::string policyName;
    std::string description;
    std::string severity;
    std::string path;
    std::string timestamp;
};

struct BaselineInfo {
    std::string id;
    std::string name;
    std::string createdAt;
    uint64_t fileCount = 0;
    std::string status;
};

enum class MonitoringStatus {
    Active,
    Paused,
    Stopped
};

struct MonitoringConfig {
    std::vector<std::string> paths;
    bool recursive = true;
    std::vector<std::string> includePatterns;
    std::vector<std::string> excludePatterns;
    int checkIntervalSeconds = 60;
};

struct LogPattern {
    std::string id;
    std::string name;
    std::string pattern;
    std::string severity;
    std::string description;
    bool enabled = true;
};

enum class RootkitType {
    HiddenProcess,
    HiddenFile,
    KernelModule,
    SyscallHook
};

struct RootkitIndicator {
    std::string id;
    RootkitType type = RootkitType::HiddenProcess;
    std::string description;
    std::string evidence;
    std::string severity;
    std::string detectedAt;
};

struct SystemLogEntry {
    std::string id;
    std::string source;
    std::string message;
    std::string level;
    std::string timestamp;
    bool matched = false;
    std::string matchedPatternId;
};

class IHIDSEngine {
public:
    virtual ~IHIDSEngine() = default;

    // Monitoring lifecycle
    virtual bool startMonitoring() = 0;
    virtual bool stopMonitoring() = 0;
    [[nodiscard]] virtual MonitoringStatus getMonitoringStatus() = 0;
    virtual bool setMonitoringConfig(const MonitoringConfig& config) = 0;

    // File integrity
    virtual std::vector<IntegrityEvent> getIntegrityEvents() = 0;
    virtual std::vector<FileChange> getFileChanges() = 0;
    virtual std::vector<PolicyViolation> getPolicyViolations() = 0;
    virtual BaselineInfo getBaseline() = 0;
    virtual std::string createBaseline(const std::string& name) = 0;
    virtual std::vector<IntegrityEvent> compareToBaseline(const std::string& baselineId) = 0;

    // Monitored path management
    virtual bool addMonitoredPath(const std::string& path) = 0;
    virtual bool removeMonitoredPath(const std::string& path) = 0;

    // Log monitoring
    virtual std::string addLogPattern(const LogPattern& pattern) = 0;
    [[nodiscard]] virtual std::vector<LogPattern> getLogPatterns() = 0;
    [[nodiscard]] virtual std::vector<SystemLogEntry> getMatchedLogEntries() = 0;

    // Rootkit detection
    virtual bool runRootkitScan() = 0;
    [[nodiscard]] virtual std::vector<RootkitIndicator> getRootkitIndicators() = 0;
};

} // namespace ThreatOne::HIDS
