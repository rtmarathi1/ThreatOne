#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Monitor {

enum class MonitorType {
    Process,
    File,
    Registry,
    Network,
    Memory,
    Performance
};

struct MonitorMetrics {
    double cpuUsage = 0.0;
    double memoryUsage = 0.0;
    double diskUsage = 0.0;
    double networkUsage = 0.0;
    uint64_t processCount = 0;
    uint64_t activeConnections = 0;
};

struct MonitorAlert {
    std::string id;
    std::string message;
    std::string severity;    // "warning", "critical"
    MonitorType type;
    std::string timestamp;
};

struct MonitorThreshold {
    MonitorType type;
    double warningLevel = 0.0;
    double criticalLevel = 0.0;
};

struct MonitorProcessInfo {
    uint64_t pid = 0;
    std::string name;
    std::string path;
    std::string commandLine;
    double cpuUsage = 0.0;
    uint64_t memoryBytes = 0;
};

struct MonitorFileEvent {
    std::string path;
    std::string action;
    std::string timestamp;
};

class IMonitorEngine {
public:
    virtual ~IMonitorEngine() = default;

    virtual bool startMonitoring(MonitorType type) = 0;
    virtual bool stopMonitoring(MonitorType type) = 0;
    virtual MonitorMetrics getMetrics() = 0;
    virtual std::vector<MonitorAlert> getAlerts() = 0;
    virtual bool setThresholds(const std::vector<MonitorThreshold>& thresholds) = 0;

    // Extended interface
    virtual std::vector<MonitorProcessInfo> getProcessList() = 0;
    virtual std::vector<MonitorFileEvent> getFileEvents() = 0;
    virtual bool isMonitoring(MonitorType type) const = 0;
};

} // namespace ThreatOne::Monitor
