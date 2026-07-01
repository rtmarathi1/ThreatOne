#pragma once

// ThreatOne Platform - MacOSDriver
// macOS-specific platform driver using EndpointSecurity framework,
// FSEvents for file monitoring, and libproc for process enumeration.

#ifdef __APPLE__

#include "platform/IPlatformDriver.h"
#include "core/Logger.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>

// Forward declarations for macOS types (avoid including heavy headers)
typedef struct __FSEventStream* FSEventStreamRef;

namespace ThreatOne::Platform {

class MacOSDriver : public IPlatformDriver {
public:
    MacOSDriver();
    ~MacOSDriver() override;

    // File monitoring using FSEvents
    Core::Result<void, Core::Error> startFileMonitoring(
        const std::string& path, FileEventCallback callback) override;
    Core::Result<void, Core::Error> stopFileMonitoring(
        const std::string& path) override;

    // Network filtering using pf (Packet Filter)
    Core::Result<void, Core::Error> addNetworkRule(
        const NetworkRule& rule) override;
    Core::Result<void, Core::Error> removeNetworkRule(
        const std::string& ruleName) override;
    Core::Result<std::vector<NetworkRule>, Core::Error> listNetworkRules() override;

    // Process monitoring using sysctl/libproc
    Core::Result<std::vector<ProcessInfo>, Core::Error> listProcesses() override;
    Core::Result<ProcessInfo, Core::Error> getProcessInfo(uint32_t pid) override;
    Core::Result<void, Core::Error> terminateProcess(uint32_t pid) override;

    // Platform identification
    std::string platformName() const override;
    bool isSupported() const override;

private:
    struct FSEventsMonitor {
        FSEventStreamRef stream;
        std::thread runLoopThread;
        std::atomic<bool> running;
        FileEventCallback callback;
        void* runLoopRef; // CFRunLoopRef stored as void*
    };

    Core::ModuleLogger logger_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<FSEventsMonitor>> monitors_;
    std::vector<NetworkRule> rules_;
};

} // namespace ThreatOne::Platform

#endif // __APPLE__
