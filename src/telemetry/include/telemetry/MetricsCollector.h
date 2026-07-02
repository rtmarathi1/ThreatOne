#pragma once

#include "telemetry/ITelemetryManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <cstdint>

namespace ThreatOne::Telemetry {

struct MetricSeries {
    std::string name;
    MetricType type = MetricType::Counter;
    std::vector<double> values;
    double sum = 0.0;
    double min = 0.0;
    double max = 0.0;
    uint64_t count = 0;
};

struct MetricBucket {
    double lowerBound = 0.0;
    double upperBound = 0.0;
    uint64_t count = 0;
};

class MetricsCollector {
public:
    MetricsCollector();
    ~MetricsCollector() = default;

    // Counter operations
    bool incrementCounter(const std::string& name, double amount = 1.0);
    [[nodiscard]] std::optional<double> getCounterValue(const std::string& name) const;

    // Gauge operations
    bool setGauge(const std::string& name, double value);
    [[nodiscard]] std::optional<double> getGaugeValue(const std::string& name) const;

    // Histogram operations
    bool recordHistogramValue(const std::string& name, double value);
    [[nodiscard]] std::vector<MetricBucket> getHistogramBuckets(const std::string& name) const;

    // Timer operations
    bool recordTimerValue(const std::string& name, double durationMs);
    [[nodiscard]] std::optional<double> getAverageTimer(const std::string& name) const;

    // Generic metric recording
    bool recordMetric(const Metric& metric);
    [[nodiscard]] std::vector<Metric> getMetrics(const std::optional<std::string>& name = std::nullopt,
                                                  const std::optional<MetricType>& type = std::nullopt) const;
    [[nodiscard]] std::optional<double> getMetricValue(const std::string& name) const;

    // Series statistics
    [[nodiscard]] std::optional<MetricSeries> getMetricSeries(const std::string& name) const;

    // Reset
    void resetMetrics();
    void resetMetric(const std::string& name);

    // Statistics
    [[nodiscard]] uint64_t getTotalMetricsRecorded() const;
    [[nodiscard]] uint64_t getUniqueMetricNames() const;

private:
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::vector<Metric> metrics_;
    std::unordered_map<std::string, MetricSeries> series_;
    uint64_t totalRecorded_ = 0;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Telemetry
