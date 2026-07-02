#pragma once

#include "plugin/IPluginManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Plugin {

struct ResourceLimits {
    uint64_t maxMemoryBytes = 104857600;  // 100MB
    uint64_t maxCpuTimeMs = 30000;        // 30 seconds
    uint64_t maxDiskBytes = 524288000;    // 500MB
    int maxFileDescriptors = 100;
    int maxNetworkConnections = 10;
};

struct SandboxStatus {
    std::string pluginId;
    bool active = false;
    uint64_t memoryUsed = 0;
    uint64_t cpuTimeUsed = 0;
    uint64_t diskUsed = 0;
    int violations = 0;
    bool faultIsolated = false;
};

class PluginSandbox {
public:
    PluginSandbox();
    ~PluginSandbox() = default;

    // Sandbox lifecycle
    bool createSandbox(const std::string& pluginId, const ResourceLimits& limits);
    bool destroySandbox(const std::string& pluginId);
    [[nodiscard]] bool hasSandbox(const std::string& pluginId) const;

    // Resource limits
    bool setResourceLimits(const std::string& pluginId, const ResourceLimits& limits);
    [[nodiscard]] ResourceLimits getResourceLimits(const std::string& pluginId) const;

    // Resource usage tracking
    bool recordMemoryUsage(const std::string& pluginId, uint64_t bytes);
    bool recordCpuUsage(const std::string& pluginId, uint64_t timeMs);
    bool recordDiskUsage(const std::string& pluginId, uint64_t bytes);

    // Status and monitoring
    [[nodiscard]] SandboxStatus getStatus(const std::string& pluginId) const;
    [[nodiscard]] std::vector<SandboxStatus> getAllStatuses() const;

    // Violation tracking
    bool recordViolation(const std::string& pluginId, const std::string& reason);
    [[nodiscard]] int getViolationCount(const std::string& pluginId) const;

    // Fault isolation
    bool isolatePlugin(const std::string& pluginId);
    bool releasePlugin(const std::string& pluginId);
    [[nodiscard]] bool isIsolated(const std::string& pluginId) const;

    // API access restriction
    bool restrictApiAccess(const std::string& pluginId, const std::vector<std::string>& blockedApis);
    [[nodiscard]] bool isApiAllowed(const std::string& pluginId, const std::string& apiName) const;

    [[nodiscard]] size_t getActiveSandboxCount() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, ResourceLimits> limits_;
    std::map<std::string, SandboxStatus> statuses_;
    std::map<std::string, std::vector<std::string>> blockedApis_;
    std::map<std::string, std::vector<std::string>> violations_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Plugin
