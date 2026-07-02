#pragma once

#include "monitor/IMonitorEngine.h"
#include "core/Logger.h"

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <vector>
#include <atomic>
#include <functional>
#include <cstddef>
#include <cstdint>
#include <string>

namespace ThreatOne::EDR {
class EDREngine;
}

namespace ThreatOne::Monitor {

class MonitorEngine : public IMonitorEngine {
public:
    MonitorEngine();
    explicit MonitorEngine(std::shared_ptr<ThreatOne::EDR::EDREngine> edrEngine);
    ~MonitorEngine() override = default;

    bool startMonitoring(MonitorType type) override;
    bool stopMonitoring(MonitorType type) override;
    MonitorMetrics getMetrics() override;
    std::vector<MonitorAlert> getAlerts() override;
    bool setThresholds(const std::vector<MonitorThreshold>& thresholds) override;

    // Extended interface
    std::vector<MonitorProcessInfo> getProcessList() override;
    std::vector<MonitorFileEvent> getFileEvents() override;
    bool isMonitoring(MonitorType type) const override;

private:
    void checkThresholds(const MonitorMetrics& metrics);
    std::string generateAlertId();
    std::string currentTimestamp() const;
    double getMetricForType(const MonitorMetrics& metrics, MonitorType type) const;

    ThreatOne::Core::ModuleLogger logger_;
    std::shared_ptr<ThreatOne::EDR::EDREngine> edrEngine_;

    struct MonitorTypeHash {
        std::size_t operator()(MonitorType t) const noexcept {
            return std::hash<int>{}(static_cast<int>(t));
        }
    };

    mutable std::mutex mutex_;
    std::unordered_set<MonitorType, MonitorTypeHash> activeMonitors_;
    std::vector<MonitorThreshold> thresholds_;
    std::vector<MonitorAlert> alerts_;
    std::atomic<uint64_t> nextAlertId_{1};
};

} // namespace ThreatOne::Monitor
