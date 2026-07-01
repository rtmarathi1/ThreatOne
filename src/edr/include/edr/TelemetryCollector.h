#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <deque>

#include "core/Logger.h"

namespace ThreatOne::EDR {

// System telemetry data point
struct TelemetryData {
    // CPU metrics
    double cpuUsagePercent = 0.0;
    double cpuUserPercent = 0.0;
    double cpuSystemPercent = 0.0;

    // Memory metrics
    uint64_t totalMemoryBytes = 0;
    uint64_t usedMemoryBytes = 0;
    uint64_t availableMemoryBytes = 0;
    double memoryUsagePercent = 0.0;

    // Disk metrics
    uint64_t diskReadBytes = 0;
    uint64_t diskWriteBytes = 0;

    // Network metrics
    uint64_t networkRxBytes = 0;
    uint64_t networkTxBytes = 0;

    // Timestamp
    std::chrono::system_clock::time_point timestamp;
};

// Anomaly detection result
struct TelemetryAnomaly {
    std::string metric; // "cpu", "memory", "disk_read", "disk_write", "network_rx", "network_tx"
    double currentValue = 0.0;
    double baselineValue = 0.0;
    double deviationFactor = 0.0; // How many standard deviations from baseline
    std::string severity; // "low", "medium", "high"
    std::chrono::system_clock::time_point timestamp;
};

class TelemetryCollector {
public:
    explicit TelemetryCollector(size_t historySize = 60);
    ~TelemetryCollector() = default;

    // Collect current system metrics
    [[nodiscard]] TelemetryData collectSystemMetrics();

    // Get historical metrics
    [[nodiscard]] std::vector<TelemetryData> getHistoricalMetrics(size_t count = 0) const;

    // Detect anomalies comparing current vs baseline
    [[nodiscard]] std::vector<TelemetryAnomaly> detectAnomalies() const;

    // Inject data for testing
    void injectMetrics(const TelemetryData& data);

    // Clear history
    void clearHistory();

private:
    struct CpuTimes {
        uint64_t user = 0;
        uint64_t nice = 0;
        uint64_t system = 0;
        uint64_t idle = 0;
        uint64_t iowait = 0;
        uint64_t irq = 0;
        uint64_t softirq = 0;
    };

    [[nodiscard]] CpuTimes readCpuTimes() const;
    [[nodiscard]] TelemetryData readMemoryInfo() const;
    [[nodiscard]] std::pair<uint64_t, uint64_t> readDiskStats() const;
    [[nodiscard]] std::pair<uint64_t, uint64_t> readNetworkStats() const;

    [[nodiscard]] double calculateMean(const std::vector<double>& values) const;
    [[nodiscard]] double calculateStdDev(const std::vector<double>& values, double mean) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    // Rolling window of historical data
    std::deque<TelemetryData> history_;
    size_t historySize_;

    // Previous CPU times for delta calculation
    CpuTimes prevCpuTimes_;
    bool hasPrevCpuTimes_ = false;

    // Previous disk/network counters for rate calculation
    uint64_t prevDiskRead_ = 0;
    uint64_t prevDiskWrite_ = 0;
    uint64_t prevNetRx_ = 0;
    uint64_t prevNetTx_ = 0;
    bool hasPrevCounters_ = false;
};

} // namespace ThreatOne::EDR
