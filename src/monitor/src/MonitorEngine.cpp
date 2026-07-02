#include "monitor/MonitorEngine.h"
#include "edr/EDREngine.h"

#include <chrono>
#include <sstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Monitor {

MonitorEngine::MonitorEngine()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("MonitorEngine"))
    , edrEngine_(std::make_shared<ThreatOne::EDR::EDREngine>())
    , systemMonitor_(std::make_shared<SystemMonitor>())
    , networkMonitor_(std::make_shared<NetworkMonitor>())
    , performanceMonitor_(std::make_shared<PerformanceMonitor>())
    , resourceTracker_(std::make_shared<ResourceTracker>())
    , healthChecker_(std::make_shared<HealthChecker>())
    , serviceWatcher_(std::make_shared<ServiceWatcher>()) {
    logger_.info("MonitorEngine initialized with internal EDR engine");
}

MonitorEngine::MonitorEngine(std::shared_ptr<ThreatOne::EDR::EDREngine> edrEngine)
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("MonitorEngine"))
    , edrEngine_(std::move(edrEngine))
    , systemMonitor_(std::make_shared<SystemMonitor>())
    , networkMonitor_(std::make_shared<NetworkMonitor>())
    , performanceMonitor_(std::make_shared<PerformanceMonitor>())
    , resourceTracker_(std::make_shared<ResourceTracker>())
    , healthChecker_(std::make_shared<HealthChecker>())
    , serviceWatcher_(std::make_shared<ServiceWatcher>()) {
    logger_.info("MonitorEngine initialized with external EDR engine");
}

bool MonitorEngine::startMonitoring(MonitorType type) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (activeMonitors_.count(type) > 0) {
        logger_.warn("Monitor type {} already active", static_cast<int>(type));
        return true;
    }

    activeMonitors_.insert(type);
    logger_.info("Started monitoring type={}", static_cast<int>(type));

    // Start EDR collection if not already running
    if (activeMonitors_.size() == 1) {
        edrEngine_->startCollection();
    }

    return true;
}

bool MonitorEngine::stopMonitoring(MonitorType type) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = activeMonitors_.find(type);
    if (it == activeMonitors_.end()) {
        logger_.warn("Monitor type {} not active", static_cast<int>(type));
        return true;
    }

    activeMonitors_.erase(it);
    logger_.info("Stopped monitoring type={}", static_cast<int>(type));

    // Stop EDR collection if no monitors active
    if (activeMonitors_.empty()) {
        edrEngine_->stopCollection();
    }

    return true;
}

MonitorMetrics MonitorEngine::getMetrics() {
    MonitorMetrics metrics;

    // Get real telemetry from EDR engine
    auto& telemetry = edrEngine_->getTelemetryCollector();
    auto data = telemetry.collectSystemMetrics();

    metrics.cpuUsage = data.cpuUsagePercent;
    metrics.memoryUsage = data.memoryUsagePercent;
    metrics.diskUsage = static_cast<double>(data.diskReadBytes + data.diskWriteBytes);
    metrics.networkUsage = static_cast<double>(data.networkRxBytes + data.networkTxBytes);

    // Get process count
    auto processes = edrEngine_->getProcesses();
    metrics.processCount = processes.size();

    // Active connections count (requires platform-specific socket enumeration)
    metrics.activeConnections = 0;

    // Feed data to performance monitor sub-component
    PerformanceSample sample;
    sample.cpuUsage = metrics.cpuUsage;
    sample.memoryUsage = metrics.memoryUsage;
    sample.diskReadRate = static_cast<double>(data.diskReadBytes);
    sample.diskWriteRate = static_cast<double>(data.diskWriteBytes);
    performanceMonitor_->addSample(sample);

    // Check thresholds
    checkThresholds(metrics);

    return metrics;
}

std::vector<MonitorAlert> MonitorEngine::getAlerts() {
    std::lock_guard<std::mutex> lock(mutex_);
    return alerts_;
}

bool MonitorEngine::setThresholds(const std::vector<MonitorThreshold>& thresholds) {
    std::lock_guard<std::mutex> lock(mutex_);
    thresholds_ = thresholds;
    logger_.info("Set {} thresholds", thresholds.size());
    return true;
}

std::vector<MonitorProcessInfo> MonitorEngine::getProcessList() {
    auto processes = edrEngine_->getProcesses();
    std::vector<MonitorProcessInfo> result;
    result.reserve(processes.size());

    for (const auto& proc : processes) {
        MonitorProcessInfo info;
        info.pid = proc.pid;
        info.name = proc.name;
        info.path = proc.path;
        info.commandLine = proc.commandLine;
        info.cpuUsage = proc.cpuUsage;
        info.memoryBytes = proc.memoryBytes;
        result.push_back(std::move(info));
    }

    return result;
}

std::vector<MonitorFileEvent> MonitorEngine::getFileEvents() {
    auto events = edrEngine_->getFileEvents();
    std::vector<MonitorFileEvent> result;
    result.reserve(events.size());

    for (const auto& event : events) {
        MonitorFileEvent fe;
        fe.path = event.path;
        fe.action = event.action;
        fe.timestamp = event.timestamp;
        result.push_back(std::move(fe));
    }

    return result;
}

bool MonitorEngine::isMonitoring(MonitorType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return activeMonitors_.count(type) > 0;
}

void MonitorEngine::checkThresholds(const MonitorMetrics& metrics) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& threshold : thresholds_) {
        double value = getMetricForType(metrics, threshold.type);

        if (threshold.criticalLevel > 0.0 && value >= threshold.criticalLevel) {
            MonitorAlert alert;
            alert.id = generateAlertId();
            alert.message = "Critical threshold breached for type " +
                            std::to_string(static_cast<int>(threshold.type)) +
                            ": value=" + std::to_string(value) +
                            " threshold=" + std::to_string(threshold.criticalLevel);
            alert.severity = "critical";
            alert.type = threshold.type;
            alert.timestamp = currentTimestamp();
            alerts_.push_back(std::move(alert));
            logger_.warn("Critical threshold breached for monitor type {}",
                        static_cast<int>(threshold.type));
        } else if (threshold.warningLevel > 0.0 && value >= threshold.warningLevel) {
            MonitorAlert alert;
            alert.id = generateAlertId();
            alert.message = "Warning threshold breached for type " +
                            std::to_string(static_cast<int>(threshold.type)) +
                            ": value=" + std::to_string(value) +
                            " threshold=" + std::to_string(threshold.warningLevel);
            alert.severity = "warning";
            alert.type = threshold.type;
            alert.timestamp = currentTimestamp();
            alerts_.push_back(std::move(alert));
        }
    }
}

std::string MonitorEngine::generateAlertId() {
    return "MALRT-" + std::to_string(nextAlertId_.fetch_add(1));
}

std::string MonitorEngine::currentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

double MonitorEngine::getMetricForType(const MonitorMetrics& metrics, MonitorType type) const {
    switch (type) {
        case MonitorType::Process:
            return static_cast<double>(metrics.processCount);
        case MonitorType::Performance:
            return metrics.cpuUsage;
        case MonitorType::Memory:
            return metrics.memoryUsage;
        case MonitorType::File:
            return metrics.diskUsage;
        case MonitorType::Network:
            return metrics.networkUsage;
        case MonitorType::Registry:
            return 0.0;
        default:
            return 0.0;
    }
}

} // namespace ThreatOne::Monitor
