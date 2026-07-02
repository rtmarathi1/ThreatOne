#include "monitor/SystemMonitor.h"

#include <algorithm>
#include <chrono>
#include <sstream>

#ifdef __linux__
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace ThreatOne::Monitor {

SystemMonitor::SystemMonitor()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("SystemMonitor")) {
    refreshSystemInfo();
    logger_.info("SystemMonitor initialized");
}

std::string SystemMonitor::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

SystemInfo SystemMonitor::getSystemInfo() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return systemInfo_;
}

uint64_t SystemMonitor::getUptime() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return systemInfo_.uptimeSeconds;
}

std::string SystemMonitor::getHostname() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return systemInfo_.hostname;
}

void SystemMonitor::addLoadedModule(const LoadedModule& module) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check for duplicate
    for (const auto& m : loadedModules_) {
        if (m.name == module.name) {
            return;
        }
    }

    LoadedModule newModule = module;
    if (newModule.loadedAt.empty()) {
        newModule.loadedAt = getCurrentTimestamp();
    }
    loadedModules_.push_back(newModule);
    logger_.info("Loaded module tracked: {}", module.name);
}

bool SystemMonitor::removeModule(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::find_if(loadedModules_.begin(), loadedModules_.end(),
                           [&name](const LoadedModule& m) { return m.name == name; });
    if (it == loadedModules_.end()) {
        return false;
    }
    loadedModules_.erase(it);
    return true;
}

std::vector<LoadedModule> SystemMonitor::getLoadedModules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return loadedModules_;
}

uint64_t SystemMonitor::getModuleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return loadedModules_.size();
}

bool SystemMonitor::refreshSystemInfo() {
    std::lock_guard<std::mutex> lock(mutex_);

#ifdef __linux__
    struct utsname buf;
    if (uname(&buf) == 0) {
        systemInfo_.hostname = buf.nodename;
        systemInfo_.osName = buf.sysname;
        systemInfo_.osVersion = buf.release;
        systemInfo_.kernelVersion = buf.version;
        systemInfo_.architecture = buf.machine;
    }
#else
    systemInfo_.hostname = "localhost";
    systemInfo_.osName = "Unknown";
    systemInfo_.osVersion = "Unknown";
    systemInfo_.kernelVersion = "Unknown";
    systemInfo_.architecture = "x86_64";
#endif

    // Calculate uptime
    auto now = std::chrono::steady_clock::now();
    systemInfo_.uptimeSeconds = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
    systemInfo_.bootTime = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())) - systemInfo_.uptimeSeconds;

    return true;
}

bool SystemMonitor::isSystemHealthy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return healthy_;
}

} // namespace ThreatOne::Monitor
