#pragma once

// ThreatOne Telemetry - Telemetry Manager Interface
// Metrics collection, health monitoring, heartbeat, feature usage tracking

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <functional>

namespace ThreatOne::Telemetry {

struct TelemetryEvent {
    std::string name;
    std::string category;
    std::unordered_map<std::string, std::string> properties;
    std::string timestamp;
};

struct UsageStats {
    uint64_t totalScans = 0;
    uint64_t threatsDetected = 0;
    uint64_t uptime = 0;
    std::string lastActive;
};

enum class MetricType {
    Counter,
    Gauge,
    Histogram,
    Timer
};

struct Metric {
    std::string name;
    MetricType type = MetricType::Counter;
    double value = 0.0;
    std::unordered_map<std::string, std::string> labels;
    std::string timestamp;
};

enum class HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown
};

struct HealthCheck {
    std::string id;
    std::string name;
    std::string component;
    HealthStatus status = HealthStatus::Unknown;
    std::string message;
    std::string lastChecked;
    double responseTimeMs = 0.0;
};

struct SystemHealth {
    HealthStatus overallStatus = HealthStatus::Unknown;
    std::vector<HealthCheck> checks;
    double uptimeSeconds = 0.0;
    double cpuUsage = 0.0;
    double memoryUsage = 0.0;
    double diskUsage = 0.0;
};

struct Heartbeat {
    std::string timestamp;
    bool healthy = false;
    std::string version;
    std::string hostname;
};

struct FeatureUsage {
    std::string featureName;
    uint64_t useCount = 0;
    std::string lastUsed;
    double averageDurationMs = 0.0;
};

class ITelemetryManager {
public:
    virtual ~ITelemetryManager() = default;

    // Event tracking
    virtual bool trackEvent(const TelemetryEvent& event) = 0;
    virtual bool trackError(const std::string& error, const std::string& context) = 0;
    [[nodiscard]] virtual std::vector<TelemetryEvent> getEvents() const = 0;
    [[nodiscard]] virtual UsageStats getUsageStats() = 0;

    // Enable/disable
    virtual void setEnabled(bool enabled) = 0;
    [[nodiscard]] virtual bool isEnabled() const = 0;

    // Metrics
    virtual bool recordMetric(const Metric& metric) = 0;
    [[nodiscard]] virtual std::vector<Metric> getMetrics(
        const std::optional<std::string>& name = std::nullopt,
        const std::optional<MetricType>& type = std::nullopt) const = 0;
    [[nodiscard]] virtual std::optional<double> getMetricValue(const std::string& name) const = 0;
    virtual void resetMetrics() = 0;

    // Health checks
    virtual std::string registerHealthCheck(const std::string& name, const std::string& component) = 0;
    virtual SystemHealth runHealthChecks() = 0;
    [[nodiscard]] virtual SystemHealth getSystemHealth() const = 0;

    // Heartbeat
    virtual bool sendHeartbeat() = 0;
    [[nodiscard]] virtual std::optional<Heartbeat> getLastHeartbeat() const = 0;

    // Feature usage tracking
    virtual bool trackFeatureUsage(const std::string& featureName, double durationMs) = 0;
    [[nodiscard]] virtual std::vector<FeatureUsage> getFeatureUsageStats() const = 0;

    // Uptime
    [[nodiscard]] virtual double getUptimeSeconds() const = 0;
};

} // namespace ThreatOne::Telemetry
