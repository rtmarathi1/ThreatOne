#pragma once

// ThreatOne Platform - LinuxDriver
// Linux-specific platform driver using inotify for file monitoring,
// iptables for network filtering, and /proc for process monitoring.

#ifdef __linux__

#include "platform/IPlatformDriver.h"
#include "core/Logger.h"

#include <unordered_map>
#include <thread>
#include <atomic>

namespace ThreatOne::Platform {

class LinuxDriver : public IPlatformDriver {
public:
    LinuxDriver();
    ~LinuxDriver() override;

    // File monitoring (inotify-based)
    Core::Result<void, Core::Error> startFileMonitoring(
        const std::string& path, FileEventCallback callback) override;
    Core::Result<void, Core::Error> stopFileMonitoring(
        const std::string& path) override;

    // Network filtering (iptables via system())
    Core::Result<void, Core::Error> addNetworkRule(
        const NetworkRule& rule) override;
    Core::Result<void, Core::Error> removeNetworkRule(
        const std::string& ruleName) override;
    Core::Result<std::vector<NetworkRule>, Core::Error> listNetworkRules() override;

    // Process monitoring (/proc-based)
    Core::Result<std::vector<ProcessInfo>, Core::Error> listProcesses() override;
    Core::Result<ProcessInfo, Core::Error> getProcessInfo(uint32_t pid) override;
    Core::Result<void, Core::Error> terminateProcess(uint32_t pid) override;

    // Platform identification
    std::string platformName() const override;
    bool isSupported() const override;

private:
    struct WatchEntry {
        int watchDescriptor = -1;
        std::string path;
        FileEventCallback callback;
    };

    Core::ModuleLogger logger_;
    int inotifyFd_ = -1;
    std::unordered_map<int, WatchEntry> watches_;
    std::unordered_map<std::string, int> pathToWd_;
    std::thread monitorThread_;
    std::atomic<bool> running_{false};

    void monitorLoop();
    static std::string buildIptablesCommand(const NetworkRule& rule, bool remove);
    ProcessInfo readProcEntry(uint32_t pid) const;
};

} // namespace ThreatOne::Platform

#endif // __linux__
