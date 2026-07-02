#include "plugin/PluginSandbox.h"
#include <mutex>

#include <algorithm>

namespace ThreatOne::Plugin {

PluginSandbox::PluginSandbox()
    : logger_("PluginSandbox") {
    logger_.info("PluginSandbox initialized");
}

bool PluginSandbox::createSandbox(const std::string& pluginId, const ResourceLimits& limits) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (statuses_.count(pluginId) > 0) {
        logger_.warn("Sandbox already exists for plugin: {}", pluginId);
        return false;
    }

    limits_[pluginId] = limits;

    SandboxStatus status;
    status.pluginId = pluginId;
    status.active = true;
    statuses_[pluginId] = status;

    logger_.info("Created sandbox for plugin: {}", pluginId);
    return true;
}

bool PluginSandbox::destroySandbox(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        logger_.warn("destroySandbox: no sandbox for plugin {}", pluginId);
        return false;
    }

    statuses_.erase(it);
    limits_.erase(pluginId);
    blockedApis_.erase(pluginId);
    violations_.erase(pluginId);

    logger_.info("Destroyed sandbox for plugin: {}", pluginId);
    return true;
}

bool PluginSandbox::hasSandbox(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return statuses_.count(pluginId) > 0;
}

bool PluginSandbox::setResourceLimits(const std::string& pluginId, const ResourceLimits& limits) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (statuses_.count(pluginId) == 0) {
        return false;
    }

    limits_[pluginId] = limits;
    logger_.info("Updated resource limits for plugin: {}", pluginId);
    return true;
}

ResourceLimits PluginSandbox::getResourceLimits(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = limits_.find(pluginId);
    if (it == limits_.end()) {
        return {};
    }
    return it->second;
}

bool PluginSandbox::recordMemoryUsage(const std::string& pluginId, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        return false;
    }

    it->second.memoryUsed = bytes;

    // Check limit
    auto limIt = limits_.find(pluginId);
    if (limIt != limits_.end() && bytes > limIt->second.maxMemoryBytes) {
        it->second.violations++;
        violations_[pluginId].push_back("memory_exceeded");
        logger_.warn("Plugin {} exceeded memory limit: {} > {}", pluginId, bytes, limIt->second.maxMemoryBytes);
    }

    return true;
}

bool PluginSandbox::recordCpuUsage(const std::string& pluginId, uint64_t timeMs) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        return false;
    }

    it->second.cpuTimeUsed = timeMs;

    auto limIt = limits_.find(pluginId);
    if (limIt != limits_.end() && timeMs > limIt->second.maxCpuTimeMs) {
        it->second.violations++;
        violations_[pluginId].push_back("cpu_exceeded");
        logger_.warn("Plugin {} exceeded CPU time limit", pluginId);
    }

    return true;
}

bool PluginSandbox::recordDiskUsage(const std::string& pluginId, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        return false;
    }

    it->second.diskUsed = bytes;

    auto limIt = limits_.find(pluginId);
    if (limIt != limits_.end() && bytes > limIt->second.maxDiskBytes) {
        it->second.violations++;
        violations_[pluginId].push_back("disk_exceeded");
        logger_.warn("Plugin {} exceeded disk limit", pluginId);
    }

    return true;
}

SandboxStatus PluginSandbox::getStatus(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        return {};
    }
    return it->second;
}

std::vector<SandboxStatus> PluginSandbox::getAllStatuses() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SandboxStatus> result;
    result.reserve(statuses_.size());
    for (const auto& [id, status] : statuses_) {
        result.push_back(status);
    }
    return result;
}

bool PluginSandbox::recordViolation(const std::string& pluginId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        return false;
    }

    it->second.violations++;
    violations_[pluginId].push_back(reason);
    logger_.warn("Recorded violation for plugin {}: {}", pluginId, reason);
    return true;
}

int PluginSandbox::getViolationCount(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        return 0;
    }
    return it->second.violations;
}

bool PluginSandbox::isolatePlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        return false;
    }

    it->second.faultIsolated = true;
    logger_.info("Isolated plugin: {}", pluginId);
    return true;
}

bool PluginSandbox::releasePlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        return false;
    }

    it->second.faultIsolated = false;
    logger_.info("Released plugin from isolation: {}", pluginId);
    return true;
}

bool PluginSandbox::isIsolated(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = statuses_.find(pluginId);
    if (it == statuses_.end()) {
        return false;
    }
    return it->second.faultIsolated;
}

bool PluginSandbox::restrictApiAccess(const std::string& pluginId, const std::vector<std::string>& apis) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (statuses_.count(pluginId) == 0) {
        return false;
    }

    blockedApis_[pluginId] = apis;
    logger_.info("Restricted {} APIs for plugin: {}", apis.size(), pluginId);
    return true;
}

bool PluginSandbox::isApiAllowed(const std::string& pluginId, const std::string& apiName) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = blockedApis_.find(pluginId);
    if (it == blockedApis_.end()) {
        return true;  // No restrictions
    }

    return std::find(it->second.begin(), it->second.end(), apiName) == it->second.end();
}

size_t PluginSandbox::getActiveSandboxCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    for (const auto& [id, status] : statuses_) {
        if (status.active) {
            count++;
        }
    }
    return count;
}

} // namespace ThreatOne::Plugin
