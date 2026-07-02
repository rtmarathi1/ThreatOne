#pragma once

#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Monitor {

struct SystemInfo {
    std::string hostname;
    std::string osName;
    std::string osVersion;
    std::string kernelVersion;
    std::string architecture;
    uint64_t bootTime = 0;
    uint64_t uptimeSeconds = 0;
};

struct LoadedModule {
    std::string name;
    std::string version;
    uint64_t size = 0;
    std::string status;
    std::string loadedAt;
};

class SystemMonitor {
public:
    SystemMonitor();
    ~SystemMonitor() = default;

    // System information
    [[nodiscard]] SystemInfo getSystemInfo() const;
    [[nodiscard]] uint64_t getUptime() const;
    [[nodiscard]] std::string getHostname() const;

    // Module tracking
    void addLoadedModule(const LoadedModule& module);
    bool removeModule(const std::string& name);
    [[nodiscard]] std::vector<LoadedModule> getLoadedModules() const;
    [[nodiscard]] uint64_t getModuleCount() const;

    // System state
    bool refreshSystemInfo();
    [[nodiscard]] bool isSystemHealthy() const;

private:
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    SystemInfo systemInfo_;
    std::vector<LoadedModule> loadedModules_;
    bool healthy_ = true;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Monitor
