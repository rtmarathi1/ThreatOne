#pragma once

// ThreatOne Telemetry - Telemetry Manager Implementation
// Metrics collection, health monitoring, heartbeat, feature usage tracking

#include "telemetry/ITelemetryManager.h"
#include "telemetry/MetricsCollector.h"
#include "telemetry/CrashReporter.h"
#include "telemetry/UsageAnalytics.h"
#include "telemetry/DiagnosticsEngine.h"
#include "telemetry/TelemetryTransport.h"
#include "telemetry/PrivacyFilter.h"
#include "core/Logger.h"

#include <chrono>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ThreatOne::Telemetry {

class TelemetryManager : public ITelemetryManager {
public:
    TelemetryManager();
    ~TelemetryManager() override = default;

    // Event tracking
    bool trackEvent(const TelemetryEvent& event) override;
    bool trackError(const std::string& error, const std::string& context) override;
    [[nodiscard]] std::vector<TelemetryEvent> getEvents() const override;
    [[nodiscard]] UsageStats getUsageStats() override;

    // Enable/disable
    void setEnabled(bool enabled) override;
    [[nodiscard]] bool isEnabled() const override;

    // Metrics
    bool recordMetric(const Metric& metric) override;
    [[nodiscard]] std::vector<Metric> getMetrics(
        const std::optional<std::string>& name = std::nullopt,
        const std::optional<MetricType>& type = std::nullopt) const override;
    [[nodiscard]] std::optional<double> getMetricValue(const std::string& name) const override;
    void resetMetrics() override;

    // Health checks
    std::string registerHealthCheck(const std::string& name, const std::string& component) override;
    SystemHealth runHealthChecks() override;
    [[nodiscard]] SystemHealth getSystemHealth() const override;

    // Heartbeat
    bool sendHeartbeat() override;
    [[nodiscard]] std::optional<Heartbeat> getLastHeartbeat() const override;

    // Feature usage tracking
    bool trackFeatureUsage(const std::string& featureName, double durationMs) override;
    [[nodiscard]] std::vector<FeatureUsage> getFeatureUsageStats() const override;

    // Uptime
    [[nodiscard]] double getUptimeSeconds() const override;

    // Access to sub-components
    [[nodiscard]] MetricsCollector& getMetricsCollector() { return *metricsCollector_; }
    [[nodiscard]] CrashReporter& getCrashReporter() { return *crashReporter_; }
    [[nodiscard]] UsageAnalytics& getUsageAnalytics() { return *usageAnalytics_; }
    [[nodiscard]] DiagnosticsEngine& getDiagnosticsEngine() { return *diagnosticsEngine_; }
    [[nodiscard]] TelemetryTransport& getTelemetryTransport() { return *telemetryTransport_; }
    [[nodiscard]] PrivacyFilter& getPrivacyFilter() { return *privacyFilter_; }

private:
    std::string generateCheckId();
    std::string getCurrentTimestamp() const;
    HealthStatus computeOverallStatus(const std::vector<HealthCheck>& checks) const;

    mutable std::mutex mutex_;
    ThreatOne::Core::ModuleLogger logger_;
    bool enabled_ = true;

    // Event storage
    std::vector<TelemetryEvent> events_;

    // Metrics storage
    std::vector<Metric> metrics_;

    // Health checks
    std::map<std::string, HealthCheck> healthChecks_;
    SystemHealth lastSystemHealth_;

    // Heartbeat
    std::optional<Heartbeat> lastHeartbeat_;

    // Feature usage
    std::unordered_map<std::string, FeatureUsage> featureUsage_;

    // Timing
    std::chrono::steady_clock::time_point startTime_;

    // ID generation
    int nextCheckId_ = 1;

    // Sub-components
    std::shared_ptr<MetricsCollector> metricsCollector_;
    std::shared_ptr<CrashReporter> crashReporter_;
    std::shared_ptr<UsageAnalytics> usageAnalytics_;
    std::shared_ptr<DiagnosticsEngine> diagnosticsEngine_;
    std::shared_ptr<TelemetryTransport> telemetryTransport_;
    std::shared_ptr<PrivacyFilter> privacyFilter_;
};

} // namespace ThreatOne::Telemetry
