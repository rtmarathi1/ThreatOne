#pragma once

// ThreatOne Platform - WindowsDriver
// Windows-specific platform driver stubs for WFP, ETW, and Windows Services.

#ifdef _WIN32

#include "platform/IPlatformDriver.h"
#include "core/Logger.h"

namespace ThreatOne::Platform {

class WindowsDriver : public IPlatformDriver {
public:
    WindowsDriver();
    ~WindowsDriver() override;

    // File monitoring (stub - would use ReadDirectoryChangesW)
    Core::Result<void, Core::Error> startFileMonitoring(
        const std::string& path, FileEventCallback callback) override;
    Core::Result<void, Core::Error> stopFileMonitoring(
        const std::string& path) override;

    // Network filtering (stub - would use WFP)
    Core::Result<void, Core::Error> addNetworkRule(
        const NetworkRule& rule) override;
    Core::Result<void, Core::Error> removeNetworkRule(
        const std::string& ruleName) override;
    Core::Result<std::vector<NetworkRule>, Core::Error> listNetworkRules() override;

    // Process monitoring (stub - would use ETW/ToolHelp32)
    Core::Result<std::vector<ProcessInfo>, Core::Error> listProcesses() override;
    Core::Result<ProcessInfo, Core::Error> getProcessInfo(uint32_t pid) override;
    Core::Result<void, Core::Error> terminateProcess(uint32_t pid) override;

    // Platform identification
    std::string platformName() const override;
    bool isSupported() const override;

private:
    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Platform

#endif // _WIN32
