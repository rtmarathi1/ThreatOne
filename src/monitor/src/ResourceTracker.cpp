#include "monitor/ResourceTracker.h"
#include <mutex>

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Monitor {

ResourceTracker::ResourceTracker()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ResourceTracker")) {
    // Set default thresholds
    thresholds_["cpu"] = 90.0;
    thresholds_["memory"] = 85.0;
    thresholds_["disk"] = 80.0;
    logger_.info("ResourceTracker initialized");
}

std::string ResourceTracker::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

void ResourceTracker::updateProcessResource(const ProcessResourceUsage& usage) {
    std::lock_guard<std::mutex> lock(mutex_);
    processResources_[usage.pid] = usage;
}

void ResourceTracker::removeProcess(uint64_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    processResources_.erase(pid);
    memoryTracking_.erase(pid);
}

std::vector<ProcessResourceUsage> ResourceTracker::getProcessResources() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ProcessResourceUsage> result;
    result.reserve(processResources_.size());
    for (const auto& [pid, usage] : processResources_) {
        result.push_back(usage);
    }
    return result;
}

ProcessResourceUsage ResourceTracker::getProcessResource(uint64_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processResources_.find(pid);
    if (it != processResources_.end()) {
        return it->second;
    }
    return {};
}

void ResourceTracker::setThreshold(const std::string& resource, double threshold) {
    std::lock_guard<std::mutex> lock(mutex_);
    thresholds_[resource] = threshold;
}

double ResourceTracker::getThreshold(const std::string& resource) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = thresholds_.find(resource);
    if (it != thresholds_.end()) {
        return it->second;
    }
    return 0.0;
}

std::vector<ResourceHog> ResourceTracker::detectResourceHogs() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ResourceHog> hogs;

    double cpuThreshold = 90.0;
    double memThreshold = 85.0;

    auto cpuIt = thresholds_.find("cpu");
    if (cpuIt != thresholds_.end()) cpuThreshold = cpuIt->second;
    auto memIt = thresholds_.find("memory");
    if (memIt != thresholds_.end()) memThreshold = memIt->second;

    for (const auto& [pid, usage] : processResources_) {
        if (usage.cpuPercent > cpuThreshold) {
            ResourceHog hog;
            hog.pid = pid;
            hog.name = usage.name;
            hog.resource = "cpu";
            hog.value = usage.cpuPercent;
            hog.threshold = cpuThreshold;
            hogs.push_back(hog);
        }
        double memPercent = static_cast<double>(usage.memoryBytes) / (1024.0 * 1024.0 * 1024.0) * 100.0;
        if (memPercent > memThreshold) {
            ResourceHog hog;
            hog.pid = pid;
            hog.name = usage.name;
            hog.resource = "memory";
            hog.value = memPercent;
            hog.threshold = memThreshold;
            hogs.push_back(hog);
        }
    }

    return hogs;
}

void ResourceTracker::trackMemoryGrowth(uint64_t pid, const std::string& name, uint64_t memoryBytes) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = memoryTracking_.find(pid);
    if (it == memoryTracking_.end()) {
        MemoryLeakSuspect suspect;
        suspect.pid = pid;
        suspect.name = name;
        suspect.initialMemory = memoryBytes;
        suspect.currentMemory = memoryBytes;
        suspect.growthRate = 0.0;
        suspect.monitoringSince = getCurrentTimestamp();
        memoryTracking_[pid] = suspect;
    } else {
        uint64_t growth = memoryBytes > it->second.currentMemory ? memoryBytes - it->second.currentMemory : 0;
        it->second.currentMemory = memoryBytes;
        it->second.growthRate = static_cast<double>(growth);
    }
}

std::vector<MemoryLeakSuspect> ResourceTracker::getMemoryLeakSuspects() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<MemoryLeakSuspect> suspects;
    for (const auto& [pid, tracking] : memoryTracking_) {
        if (tracking.currentMemory > tracking.initialMemory * 2) {
            suspects.push_back(tracking);
        }
    }
    return suspects;
}

void ResourceTracker::clearMemoryTracking() {
    std::lock_guard<std::mutex> lock(mutex_);
    memoryTracking_.clear();
}

std::vector<ProcessResourceUsage> ResourceTracker::getTopCpuConsumers(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ProcessResourceUsage> sorted;
    sorted.reserve(processResources_.size());
    for (const auto& [pid, usage] : processResources_) {
        sorted.push_back(usage);
    }

    std::sort(sorted.begin(), sorted.end(),
              [](const ProcessResourceUsage& a, const ProcessResourceUsage& b) {
                  return a.cpuPercent > b.cpuPercent;
              });

    if (sorted.size() > count) {
        sorted.resize(count);
    }
    return sorted;
}

std::vector<ProcessResourceUsage> ResourceTracker::getTopMemoryConsumers(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ProcessResourceUsage> sorted;
    sorted.reserve(processResources_.size());
    for (const auto& [pid, usage] : processResources_) {
        sorted.push_back(usage);
    }

    std::sort(sorted.begin(), sorted.end(),
              [](const ProcessResourceUsage& a, const ProcessResourceUsage& b) {
                  return a.memoryBytes > b.memoryBytes;
              });

    if (sorted.size() > count) {
        sorted.resize(count);
    }
    return sorted;
}

uint64_t ResourceTracker::getTrackedProcessCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return processResources_.size();
}

uint64_t ResourceTracker::getTotalMemoryUsed() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t total = 0;
    for (const auto& [pid, usage] : processResources_) {
        total += usage.memoryBytes;
    }
    return total;
}

} // namespace ThreatOne::Monitor
