#include "telemetry/MetricsCollector.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Telemetry {

MetricsCollector::MetricsCollector()
    : logger_(Core::Logger::instance().getModuleLogger("MetricsCollector")) {
    logger_.info("MetricsCollector initialized");
}

std::string MetricsCollector::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

bool MetricsCollector::incrementCounter(const std::string& name, double amount) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& series = series_[name];
    series.name = name;
    series.type = MetricType::Counter;
    series.sum += amount;
    series.count++;
    series.values.push_back(series.sum);
    if (series.count == 1) { series.min = series.sum; series.max = series.sum; }
    else { series.min = std::min(series.min, series.sum); series.max = std::max(series.max, series.sum); }

    Metric m;
    m.name = name;
    m.type = MetricType::Counter;
    m.value = series.sum;
    m.timestamp = getCurrentTimestamp();
    metrics_.push_back(m);
    ++totalRecorded_;
    return true;
}

std::optional<double> MetricsCollector::getCounterValue(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = series_.find(name);
    if (it == series_.end() || it->second.type != MetricType::Counter) {
        return std::nullopt;
    }
    return it->second.sum;
}

bool MetricsCollector::setGauge(const std::string& name, double value) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& series = series_[name];
    series.name = name;
    series.type = MetricType::Gauge;
    series.sum = value;
    series.count++;
    series.values.push_back(value);
    if (series.count == 1) { series.min = value; series.max = value; }
    else { series.min = std::min(series.min, value); series.max = std::max(series.max, value); }

    Metric m;
    m.name = name;
    m.type = MetricType::Gauge;
    m.value = value;
    m.timestamp = getCurrentTimestamp();
    metrics_.push_back(m);
    ++totalRecorded_;
    return true;
}

std::optional<double> MetricsCollector::getGaugeValue(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = series_.find(name);
    if (it == series_.end() || it->second.type != MetricType::Gauge) {
        return std::nullopt;
    }
    return it->second.sum;
}

bool MetricsCollector::recordHistogramValue(const std::string& name, double value) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& series = series_[name];
    series.name = name;
    series.type = MetricType::Histogram;
    series.sum += value;
    series.count++;
    series.values.push_back(value);
    if (series.count == 1) { series.min = value; series.max = value; }
    else { series.min = std::min(series.min, value); series.max = std::max(series.max, value); }

    Metric m;
    m.name = name;
    m.type = MetricType::Histogram;
    m.value = value;
    m.timestamp = getCurrentTimestamp();
    metrics_.push_back(m);
    ++totalRecorded_;
    return true;
}

std::vector<MetricBucket> MetricsCollector::getHistogramBuckets(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = series_.find(name);
    if (it == series_.end()) {
        return {};
    }

    // Create default buckets: [0-10), [10-50), [50-100), [100-500), [500+)
    std::vector<MetricBucket> buckets;
    double bounds[] = {0, 10, 50, 100, 500, 1e12};
    for (int i = 0; i < 5; ++i) {
        MetricBucket bucket;
        bucket.lowerBound = bounds[i];
        bucket.upperBound = bounds[i + 1];
        bucket.count = 0;
        for (double val : it->second.values) {
            if (val >= bucket.lowerBound && val < bucket.upperBound) {
                bucket.count++;
            }
        }
        buckets.push_back(bucket);
    }
    return buckets;
}

bool MetricsCollector::recordTimerValue(const std::string& name, double durationMs) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& series = series_[name];
    series.name = name;
    series.type = MetricType::Timer;
    series.sum += durationMs;
    series.count++;
    series.values.push_back(durationMs);
    if (series.count == 1) { series.min = durationMs; series.max = durationMs; }
    else { series.min = std::min(series.min, durationMs); series.max = std::max(series.max, durationMs); }

    Metric m;
    m.name = name;
    m.type = MetricType::Timer;
    m.value = durationMs;
    m.timestamp = getCurrentTimestamp();
    metrics_.push_back(m);
    ++totalRecorded_;
    return true;
}

std::optional<double> MetricsCollector::getAverageTimer(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = series_.find(name);
    if (it == series_.end() || it->second.count == 0) {
        return std::nullopt;
    }
    return it->second.sum / static_cast<double>(it->second.count);
}

bool MetricsCollector::recordMetric(const Metric& metric) {
    std::lock_guard<std::mutex> lock(mutex_);

    Metric stored = metric;
    if (stored.timestamp.empty()) {
        stored.timestamp = getCurrentTimestamp();
    }
    metrics_.push_back(stored);
    ++totalRecorded_;

    auto& series = series_[metric.name];
    series.name = metric.name;
    series.type = metric.type;
    series.sum += metric.value;
    series.count++;
    series.values.push_back(metric.value);
    if (series.count == 1) { series.min = metric.value; series.max = metric.value; }
    else { series.min = std::min(series.min, metric.value); series.max = std::max(series.max, metric.value); }

    return true;
}

std::vector<Metric> MetricsCollector::getMetrics(const std::optional<std::string>& name,
                                                  const std::optional<MetricType>& type) const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!name.has_value() && !type.has_value()) {
        return metrics_;
    }

    std::vector<Metric> result;
    for (const auto& m : metrics_) {
        bool nameMatch = !name.has_value() || m.name == name.value();
        bool typeMatch = !type.has_value() || m.type == type.value();
        if (nameMatch && typeMatch) {
            result.push_back(m);
        }
    }
    return result;
}

std::optional<double> MetricsCollector::getMetricValue(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto it = metrics_.rbegin(); it != metrics_.rend(); ++it) {
        if (it->name == name) {
            return it->value;
        }
    }
    return std::nullopt;
}

std::optional<MetricSeries> MetricsCollector::getMetricSeries(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = series_.find(name);
    if (it == series_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void MetricsCollector::resetMetrics() {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.clear();
    series_.clear();
}

void MetricsCollector::resetMetric(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    series_.erase(name);
    metrics_.erase(
        std::remove_if(metrics_.begin(), metrics_.end(),
                       [&name](const Metric& m) { return m.name == name; }),
        metrics_.end());
}

uint64_t MetricsCollector::getTotalMetricsRecorded() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalRecorded_;
}

uint64_t MetricsCollector::getUniqueMetricNames() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return series_.size();
}

} // namespace ThreatOne::Telemetry
