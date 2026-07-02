#pragma once

#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Monitor {

struct ProcessResourceUsage {
    uint64_t pid = 0;
    std::string name;
    double cpuPercent = 0.0;
    uint64_t memoryBytes = 0;
    uint64_t diskReadBytes = 0;
    uint64_t diskWriteBytes = 0;
    uint64_t openFiles = 0;
    uint64_t threads = 0;
    std::string status;
};

struct ResourceHog {
    uint64_t pid = 0;
    std::string name;
    std::string resource;  // "cpu", "memory", "disk"
    double value = 0.0;
    double threshold = 0.0;
    std::string detectedAt;
};

struct MemoryLeakSuspect {
    uint64_t pid = 0;
    std::string name;
    uint64_t initialMemory = 0;
    uint64_t currentMemory = 0;
    double growthRate = 0.0;  // bytes per second
    std::string monitoringSince;
};

class ResourceTracker {
public:
    ResourceTracker();
    ~ResourceTracker() = default;

    // Process tracking
    void updateProcessResource(const ProcessResourceUsage& usage);
    void removeProcess(uint64_t pid);
    [[nodiscard]] std::vector<ProcessResourceUsage> getProcessResources() const;
    [[nodiscard]] ProcessResourceUsage getProcessResource(uint64_t pid) const;

    // Resource hog detection
    void setThreshold(const std::string& resource, double threshold);
    [[nodiscard]] std::vector<ResourceHog> detectResourceHogs() const;
    [[nodiscard]] double getThreshold(const std::string& resource) const;

    // Memory leak detection
    void trackMemoryGrowth(uint64_t pid, const std::string& name, uint64_t memoryBytes);
    [[nodiscard]] std::vector<MemoryLeakSuspect> getMemoryLeakSuspects() const;
    void clearMemoryTracking();

    // Top consumers
    [[nodiscard]] std::vector<ProcessResourceUsage> getTopCpuConsumers(size_t count) const;
    [[nodiscard]] std::vector<ProcessResourceUsage> getTopMemoryConsumers(size_t count) const;

    // Stats
    [[nodiscard]] uint64_t getTrackedProcessCount() const;
    [[nodiscard]] uint64_t getTotalMemoryUsed() const;

private:
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::map<uint64_t, ProcessResourceUsage> processResources_;
    std::map<std::string, double> thresholds_;
    std::map<uint64_t, MemoryLeakSuspect> memoryTracking_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Monitor
