#pragma once

#include <string>
#include <vector>
#include <unordered_map>

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
    std::string severity;
    MonitorType type;
    std::string timestamp;
};

struct MonitorThreshold {
    MonitorType type;
    double warningLevel = 0.0;
    double criticalLevel = 0.0;
};

class IMonitorEngine {
public:
    virtual ~IMonitorEngine() = default;

    virtual bool startMonitoring(MonitorType type) = 0;
    virtual bool stopMonitoring(MonitorType type) = 0;
    virtual MonitorMetrics getMetrics() = 0;
    virtual std::vector<MonitorAlert> getAlerts() = 0;
    virtual bool setThresholds(const std::vector<MonitorThreshold>& thresholds) = 0;
};

} // namespace ThreatOne::Monitor
