#include "telemetry/TelemetryManager.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <sstream>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Telemetry {

TelemetryManager::TelemetryManager()
    : logger_("TelemetryManager")
    , startTime_(std::chrono::steady_clock::now())
    , metricsCollector_(std::make_shared<MetricsCollector>())
    , crashReporter_(std::make_shared<CrashReporter>())
    , usageAnalytics_(std::make_shared<UsageAnalytics>())
    , diagnosticsEngine_(std::make_shared<DiagnosticsEngine>())
    , telemetryTransport_(std::make_shared<TelemetryTransport>())
    , privacyFilter_(std::make_shared<PrivacyFilter>()) {
    logger_.info("TelemetryManager initialized");
}

std::string TelemetryManager::generateCheckId() {
    std::ostringstream oss;
    oss << "HC-" << nextCheckId_;
    ++nextCheckId_;
    return oss.str();
}

std::string TelemetryManager::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

HealthStatus TelemetryManager::computeOverallStatus(const std::vector<HealthCheck>& checks) const {
    if (checks.empty()) {
        return HealthStatus::Unknown;
    }

    HealthStatus worst = HealthStatus::Healthy;
    for (const auto& check : checks) {
        // Unhealthy is the worst
        if (check.status == HealthStatus::Unhealthy) {
            return HealthStatus::Unhealthy;
        }
        // Degraded is worse than Healthy/Unknown
        if (check.status == HealthStatus::Degraded) {
            worst = HealthStatus::Degraded;
        }
        // Unknown is worse than Healthy but not as bad as Degraded
        if (check.status == HealthStatus::Unknown && worst == HealthStatus::Healthy) {
            worst = HealthStatus::Unknown;
        }
    }
    return worst;
}

bool TelemetryManager::trackEvent(const TelemetryEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!enabled_) {
        return false;
    }

    TelemetryEvent stored = event;
    if (stored.timestamp.empty()) {
        stored.timestamp = getCurrentTimestamp();
    }

    events_.push_back(std::move(stored));
    logger_.info("Tracked event: {}", event.name);
    return true;
}

bool TelemetryManager::trackError(const std::string& error, const std::string& context) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!enabled_) {
        return false;
    }

    TelemetryEvent errorEvent;
    errorEvent.name = error;
    errorEvent.category = "error";
    errorEvent.properties["context"] = context;
    errorEvent.timestamp = getCurrentTimestamp();

    events_.push_back(std::move(errorEvent));
    logger_.info("Tracked error: {} ({})", error, context);
    return true;
}

std::vector<TelemetryEvent> TelemetryManager::getEvents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_;
}

UsageStats TelemetryManager::getUsageStats() {
    std::lock_guard<std::mutex> lock(mutex_);

    UsageStats stats;
    stats.totalScans = 0;
    stats.threatsDetected = 0;
    stats.uptime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startTime_).count());
    stats.lastActive = getCurrentTimestamp();

    // Count scan and threat events
    for (const auto& event : events_) {
        if (event.category == "scan") {
            ++stats.totalScans;
        }
        if (event.category == "threat") {
            ++stats.threatsDetected;
        }
    }

    return stats;
}

void TelemetryManager::setEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = enabled;
    logger_.info("Telemetry enabled: {}", enabled);
}

bool TelemetryManager::isEnabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return enabled_;
}

bool TelemetryManager::recordMetric(const Metric& metric) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!enabled_) {
        return false;
    }

    Metric stored = metric;
    if (stored.timestamp.empty()) {
        stored.timestamp = getCurrentTimestamp();
    }

    metrics_.push_back(std::move(stored));
    logger_.info("Recorded metric: {} = {}", metric.name, metric.value);
    return true;
}

std::vector<Metric> TelemetryManager::getMetrics(
    const std::optional<std::string>& name,
    const std::optional<MetricType>& type) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!name.has_value() && !type.has_value()) {
        return metrics_;
    }

    std::vector<Metric> result;
    for (const auto& metric : metrics_) {
        bool nameMatch = !name.has_value() || metric.name == name.value();
        bool typeMatch = !type.has_value() || metric.type == type.value();
        if (nameMatch && typeMatch) {
            result.push_back(metric);
        }
    }
    return result;
}

std::optional<double> TelemetryManager::getMetricValue(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Return the most recent metric value with the given name
    for (auto it = metrics_.rbegin(); it != metrics_.rend(); ++it) {
        if (it->name == name) {
            return it->value;
        }
    }
    return std::nullopt;
}

void TelemetryManager::resetMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.clear();
    logger_.info("Metrics reset");
}

std::string TelemetryManager::registerHealthCheck(const std::string& name, const std::string& component) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string checkId = generateCheckId();

    HealthCheck check;
    check.id = checkId;
    check.name = name;
    check.component = component;
    check.status = HealthStatus::Unknown;
    check.message = "Not yet checked";
    check.lastChecked = "";
    check.responseTimeMs = 0.0;

    healthChecks_[checkId] = check;
    logger_.info("Registered health check: {} ({}) -> {}", name, component, checkId);
    return checkId;
}

SystemHealth TelemetryManager::runHealthChecks() {
    std::lock_guard<std::mutex> lock(mutex_);

    SystemHealth health;
    health.uptimeSeconds = std::chrono::duration_cast<std::chrono::duration<double>>(
        std::chrono::steady_clock::now() - startTime_).count();

    std::string now = getCurrentTimestamp();

    for (auto& [id, check] : healthChecks_) {
        // Simulate running the check - mark as healthy by default
        // In a real implementation, this would invoke a registered check function
        check.status = HealthStatus::Healthy;
        check.message = "OK";
        check.lastChecked = now;
        check.responseTimeMs = 1.0;  // Simulated response time
        health.checks.push_back(check);
    }

    health.overallStatus = computeOverallStatus(health.checks);
    health.cpuUsage = 0.0;
    health.memoryUsage = 0.0;
    health.diskUsage = 0.0;

    lastSystemHealth_ = health;
    logger_.info("Health checks completed: {} checks, overall status: {}",
                 health.checks.size(), static_cast<int>(health.overallStatus));
    return health;
}

SystemHealth TelemetryManager::getSystemHealth() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastSystemHealth_;
}

bool TelemetryManager::sendHeartbeat() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!enabled_) {
        return false;
    }

    Heartbeat heartbeat;
    heartbeat.timestamp = getCurrentTimestamp();
    heartbeat.version = "1.0.0";
    heartbeat.hostname = "localhost";

    // Determine health from last known system health
    heartbeat.healthy = (lastSystemHealth_.overallStatus == HealthStatus::Healthy ||
                         lastSystemHealth_.overallStatus == HealthStatus::Unknown);

    lastHeartbeat_ = heartbeat;
    logger_.info("Heartbeat sent: healthy={}", heartbeat.healthy);
    return true;
}

std::optional<Heartbeat> TelemetryManager::getLastHeartbeat() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastHeartbeat_;
}

bool TelemetryManager::trackFeatureUsage(const std::string& featureName, double durationMs) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!enabled_) {
        return false;
    }

    auto it = featureUsage_.find(featureName);
    if (it == featureUsage_.end()) {
        FeatureUsage usage;
        usage.featureName = featureName;
        usage.useCount = 1;
        usage.lastUsed = getCurrentTimestamp();
        usage.averageDurationMs = durationMs;
        featureUsage_[featureName] = usage;
    } else {
        auto& usage = it->second;
        // Compute new running average
        double totalDuration = usage.averageDurationMs * static_cast<double>(usage.useCount);
        usage.useCount++;
        usage.averageDurationMs = (totalDuration + durationMs) / static_cast<double>(usage.useCount);
        usage.lastUsed = getCurrentTimestamp();
    }

    logger_.info("Feature usage tracked: {} ({}ms)", featureName, durationMs);
    return true;
}

std::vector<FeatureUsage> TelemetryManager::getFeatureUsageStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<FeatureUsage> result;
    result.reserve(featureUsage_.size());
    for (const auto& [name, usage] : featureUsage_) {
        result.push_back(usage);
    }
    return result;
}

double TelemetryManager::getUptimeSeconds() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::chrono::duration_cast<std::chrono::duration<double>>(
        std::chrono::steady_clock::now() - startTime_).count();
}

} // namespace ThreatOne::Telemetry
