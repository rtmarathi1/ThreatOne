#pragma once

// ThreatOne Platform - MacOSDriver
// macOS-specific platform driver stubs for EndpointSecurity framework
// and Network Extension.

#ifdef __APPLE__

#include "platform/IPlatformDriver.h"
#include "core/Logger.h"

namespace ThreatOne::Platform {

class MacOSDriver : public IPlatformDriver {
public:
    MacOSDriver();
    ~MacOSDriver() override;

    // File monitoring (stub - would use FSEvents/EndpointSecurity)
    Core::Result<void, Core::Error> startFileMonitoring(
        const std::string& path, FileEventCallback callback) override;
    Core::Result<void, Core::Error> stopFileMonitoring(
        const std::string& path) override;

    // Network filtering (stub - would use Network Extension)
    Core::Result<void, Core::Error> addNetworkRule(
        const NetworkRule& rule) override;
    Core::Result<void, Core::Error> removeNetworkRule(
        const std::string& ruleName) override;
    Core::Result<std::vector<NetworkRule>, Core::Error> listNetworkRules() override;

    // Process monitoring (stub - would use EndpointSecurity/libproc)
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

#endif // __APPLE__
