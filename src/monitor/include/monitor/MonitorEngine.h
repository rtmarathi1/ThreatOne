#pragma once

#include "monitor/IMonitorEngine.h"
#include "core/Logger.h"

namespace ThreatOne::Monitor {

class MonitorEngine : public IMonitorEngine {
public:
    MonitorEngine();
    ~MonitorEngine() override = default;

    bool startMonitoring(MonitorType type) override;
    bool stopMonitoring(MonitorType type) override;
    MonitorMetrics getMetrics() override;
    std::vector<MonitorAlert> getAlerts() override;
    bool setThresholds(const std::vector<MonitorThreshold>& thresholds) override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Monitor
