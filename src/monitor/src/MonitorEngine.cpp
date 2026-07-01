#include "monitor/MonitorEngine.h"

namespace ThreatOne::Monitor {

MonitorEngine::MonitorEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("MonitorEngine")) {
    logger_.info("MonitorEngine initialized (stub)");
}

bool MonitorEngine::startMonitoring(MonitorType type) {
    logger_.info("startMonitoring called, type={}", static_cast<int>(type));
    return true;
}

bool MonitorEngine::stopMonitoring(MonitorType type) {
    logger_.info("stopMonitoring called, type={}", static_cast<int>(type));
    return true;
}

MonitorMetrics MonitorEngine::getMetrics() {
    logger_.info("getMetrics called");
    return {15.0, 45.0, 30.0, 5.0, 128, 42};
}

std::vector<MonitorAlert> MonitorEngine::getAlerts() {
    logger_.info("getAlerts called");
    return {};
}

bool MonitorEngine::setThresholds(const std::vector<MonitorThreshold>& thresholds) {
    logger_.info("setThresholds called with {} thresholds", thresholds.size());
    return true;
}

} // namespace ThreatOne::Monitor
