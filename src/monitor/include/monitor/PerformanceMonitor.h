#pragma once

#include "core/Logger.h"

#include <mutex>
#include <deque>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Monitor {

struct PerformanceSample {
    double cpuUsage = 0.0;
    double memoryUsage = 0.0;
    double diskReadRate = 0.0;
    double diskWriteRate = 0.0;
    double gpuUsage = 0.0;
    uint64_t timestamp = 0;
};

struct PerformanceAverage {
    double avgCpu = 0.0;
    double avgMemory = 0.0;
    double avgDiskRead = 0.0;
    double avgDiskWrite = 0.0;
    double avgGpu = 0.0;
    uint64_t sampleCount = 0;
    uint64_t windowSeconds = 0;
};

struct PerformancePeak {
    double peakCpu = 0.0;
    double peakMemory = 0.0;
    double peakDiskRead = 0.0;
    double peakDiskWrite = 0.0;
    double peakGpu = 0.0;
};

class PerformanceMonitor {
public:
    PerformanceMonitor();
    ~PerformanceMonitor() = default;

    // Sampling
    void addSample(const PerformanceSample& sample);
    [[nodiscard]] PerformanceSample getLatestSample() const;
    [[nodiscard]] std::vector<PerformanceSample> getRecentSamples(size_t count) const;

    // Averages
    [[nodiscard]] PerformanceAverage getAverage(uint64_t windowSeconds = 300) const;
    [[nodiscard]] PerformancePeak getPeaks() const;

    // Current values
    [[nodiscard]] double getCurrentCpuUsage() const;
    [[nodiscard]] double getCurrentMemoryUsage() const;
    [[nodiscard]] double getCurrentDiskUsage() const;

    // Configuration
    void setSamplingInterval(uint64_t intervalMs);
    [[nodiscard]] uint64_t getSamplingInterval() const;
    void setMaxSamples(size_t max);

    // Stats
    [[nodiscard]] uint64_t getTotalSamplesCollected() const;
    void clearSamples();

private:
    mutable std::mutex mutex_;
    std::deque<PerformanceSample> samples_;
    size_t maxSamples_ = 10000;
    uint64_t samplingIntervalMs_ = 1000;
    uint64_t totalSamplesCollected_ = 0;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Monitor
