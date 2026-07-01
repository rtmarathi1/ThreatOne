#pragma once

// ThreatOne Platform - WindowsDriver
// Windows-specific platform driver using WFP, ETW, and Win32 APIs.
// Compiles on Windows with full implementations; on other platforms,
// returns platform-not-supported errors.

#ifdef _WIN32

#include "platform/IPlatformDriver.h"
#include "core/Logger.h"

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>

namespace ThreatOne::Platform {

class WindowsDriver : public IPlatformDriver {
public:
    WindowsDriver();
    ~WindowsDriver() override;

    // File monitoring using ReadDirectoryChangesW
    Core::Result<void, Core::Error> startFileMonitoring(
        const std::string& path, FileEventCallback callback) override;
    Core::Result<void, Core::Error> stopFileMonitoring(
        const std::string& path) override;

    // Network filtering using Windows Filtering Platform (WFP)
    Core::Result<void, Core::Error> addNetworkRule(
        const NetworkRule& rule) override;
    Core::Result<void, Core::Error> removeNetworkRule(
        const std::string& ruleName) override;
    Core::Result<std::vector<NetworkRule>, Core::Error> listNetworkRules() override;

    // Process monitoring using ToolHelp32 snapshot API
    Core::Result<std::vector<ProcessInfo>, Core::Error> listProcesses() override;
    Core::Result<ProcessInfo, Core::Error> getProcessInfo(uint32_t pid) override;
    Core::Result<void, Core::Error> terminateProcess(uint32_t pid) override;

    // Platform identification
    std::string platformName() const override;
    bool isSupported() const override;

private:
    struct MonitorHandle {
        HANDLE dirHandle;
        std::thread watchThread;
        std::atomic<bool> running;
        FileEventCallback callback;
    };

    Core::ModuleLogger logger_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<MonitorHandle>> monitors_;
    std::vector<NetworkRule> rules_;

    void watchDirectory(MonitorHandle* handle, const std::string& path);
};

} // namespace ThreatOne::Platform

#endif // _WIN32
