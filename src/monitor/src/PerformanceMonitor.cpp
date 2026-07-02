#include "monitor/PerformanceMonitor.h"
#include <mutex>

#include <algorithm>
#include <chrono>

namespace ThreatOne::Monitor {

PerformanceMonitor::PerformanceMonitor()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("PerformanceMonitor")) {
    logger_.info("PerformanceMonitor initialized");
}

void PerformanceMonitor::addSample(const PerformanceSample& sample) {
    std::lock_guard<std::mutex> lock(mutex_);

    PerformanceSample newSample = sample;
    if (newSample.timestamp == 0) {
        auto now = std::chrono::system_clock::now();
        newSample.timestamp = static_cast<uint64_t>(
            std::chrono::system_clock::to_time_t(now));
    }

    samples_.push_back(newSample);
    if (samples_.size() > maxSamples_) {
        samples_.pop_front();
    }
    totalSamplesCollected_++;
}

PerformanceSample PerformanceMonitor::getLatestSample() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (samples_.empty()) {
        return {};
    }
    return samples_.back();
}

std::vector<PerformanceSample> PerformanceMonitor::getRecentSamples(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PerformanceSample> result;
    size_t start = samples_.size() > count ? samples_.size() - count : 0;
    for (size_t i = start; i < samples_.size(); ++i) {
        result.push_back(samples_[i]);
    }
    return result;
}

PerformanceAverage PerformanceMonitor::getAverage(uint64_t windowSeconds) const {
    std::lock_guard<std::mutex> lock(mutex_);

    PerformanceAverage avg;
    avg.windowSeconds = windowSeconds;

    if (samples_.empty()) {
        return avg;
    }

    auto now = std::chrono::system_clock::now();
    uint64_t currentTime = static_cast<uint64_t>(std::chrono::system_clock::to_time_t(now));
    uint64_t cutoff = currentTime > windowSeconds ? currentTime - windowSeconds : 0;

    double totalCpu = 0.0, totalMem = 0.0, totalDr = 0.0, totalDw = 0.0, totalGpu = 0.0;
    uint64_t count = 0;

    for (const auto& sample : samples_) {
        if (sample.timestamp >= cutoff) {
            totalCpu += sample.cpuUsage;
            totalMem += sample.memoryUsage;
            totalDr += sample.diskReadRate;
            totalDw += sample.diskWriteRate;
            totalGpu += sample.gpuUsage;
            count++;
        }
    }

    if (count > 0) {
        avg.avgCpu = totalCpu / static_cast<double>(count);
        avg.avgMemory = totalMem / static_cast<double>(count);
        avg.avgDiskRead = totalDr / static_cast<double>(count);
        avg.avgDiskWrite = totalDw / static_cast<double>(count);
        avg.avgGpu = totalGpu / static_cast<double>(count);
    }
    avg.sampleCount = count;

    return avg;
}

PerformancePeak PerformanceMonitor::getPeaks() const {
    std::lock_guard<std::mutex> lock(mutex_);

    PerformancePeak peaks;

    for (const auto& sample : samples_) {
        if (sample.cpuUsage > peaks.peakCpu) peaks.peakCpu = sample.cpuUsage;
        if (sample.memoryUsage > peaks.peakMemory) peaks.peakMemory = sample.memoryUsage;
        if (sample.diskReadRate > peaks.peakDiskRead) peaks.peakDiskRead = sample.diskReadRate;
        if (sample.diskWriteRate > peaks.peakDiskWrite) peaks.peakDiskWrite = sample.diskWriteRate;
        if (sample.gpuUsage > peaks.peakGpu) peaks.peakGpu = sample.gpuUsage;
    }

    return peaks;
}

double PerformanceMonitor::getCurrentCpuUsage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (samples_.empty()) return 0.0;
    return samples_.back().cpuUsage;
}

double PerformanceMonitor::getCurrentMemoryUsage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (samples_.empty()) return 0.0;
    return samples_.back().memoryUsage;
}

double PerformanceMonitor::getCurrentDiskUsage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (samples_.empty()) return 0.0;
    return samples_.back().diskReadRate + samples_.back().diskWriteRate;
}

void PerformanceMonitor::setSamplingInterval(uint64_t intervalMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    samplingIntervalMs_ = intervalMs;
}

uint64_t PerformanceMonitor::getSamplingInterval() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return samplingIntervalMs_;
}

void PerformanceMonitor::setMaxSamples(size_t max) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxSamples_ = max;
    while (samples_.size() > maxSamples_) {
        samples_.pop_front();
    }
}

uint64_t PerformanceMonitor::getTotalSamplesCollected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return totalSamplesCollected_;
}

void PerformanceMonitor::clearSamples() {
    std::lock_guard<std::mutex> lock(mutex_);
    samples_.clear();
}

} // namespace ThreatOne::Monitor
