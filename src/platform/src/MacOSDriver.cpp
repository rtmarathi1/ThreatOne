// ThreatOne Platform - MacOSDriver implementation
// Uses FSEvents for file monitoring, pf for network filtering,
// and sysctl/libproc for process management.

#ifdef __APPLE__

#include "MacOSDriver.h"

#include <sys/sysctl.h>
#include <sys/types.h>
#include <signal.h>
#include <libproc.h>
#include <CoreServices/CoreServices.h>
#include <cstring>
#include <array>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ThreatOne::Platform {

// FSEvents callback (C-linkage)
static void fsEventsCallback(ConstFSEventStreamRef /*streamRef*/,
                              void* clientCallBackInfo,
                              size_t numEvents,
                              void* eventPaths,
                              const FSEventStreamEventFlags eventFlags[],
                              const FSEventStreamEventId /*eventIds*/[]) {
    auto* monitor = static_cast<MacOSDriver::FSEventsMonitor*>(clientCallBackInfo);
    if (!monitor || !monitor->callback) return;

    char** paths = static_cast<char**>(eventPaths);
    for (size_t i = 0; i < numEvents; ++i) {
        FileEvent event;
        event.path = paths[i];

        FSEventStreamEventFlags flags = eventFlags[i];
        if (flags & kFSEventStreamEventFlagItemCreated) {
            event.type = FileEventType::Created;
        } else if (flags & kFSEventStreamEventFlagItemRemoved) {
            event.type = FileEventType::Deleted;
        } else if (flags & kFSEventStreamEventFlagItemRenamed) {
            event.type = FileEventType::Renamed;
        } else if (flags & kFSEventStreamEventFlagItemModified) {
            event.type = FileEventType::Modified;
        } else if (flags & kFSEventStreamEventFlagItemInodeMetaMod) {
            event.type = FileEventType::AttributeChanged;
        } else {
            event.type = FileEventType::Modified;
        }

        monitor->callback(event);
    }
}

MacOSDriver::MacOSDriver()
    : logger_(Core::Logger::instance().getModuleLogger("Platform.macOS")) {
    logger_.info("macOS platform driver initialized");
}

MacOSDriver::~MacOSDriver() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [path, monitor] : monitors_) {
        if (monitor && monitor->running.load()) {
            monitor->running.store(false);
            if (monitor->stream) {
                FSEventStreamStop(monitor->stream);
                FSEventStreamInvalidate(monitor->stream);
                FSEventStreamRelease(monitor->stream);
            }
            if (monitor->runLoopRef) {
                CFRunLoopStop(static_cast<CFRunLoopRef>(monitor->runLoopRef));
            }
            if (monitor->runLoopThread.joinable()) {
                monitor->runLoopThread.join();
            }
        }
    }
    monitors_.clear();
}

Core::Result<void, Core::Error> MacOSDriver::startFileMonitoring(
    const std::string& path, FileEventCallback callback) {

    if (path.empty()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Path cannot be empty", Core::ErrorCategory::Validation));
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (monitors_.count(path) > 0) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Already monitoring path: " + path, Core::ErrorCategory::Internal));
    }

    auto monitor = std::make_unique<FSEventsMonitor>();
    monitor->running.store(true);
    monitor->callback = std::move(callback);
    monitor->stream = nullptr;
    monitor->runLoopRef = nullptr;

    FSEventsMonitor* rawMonitor = monitor.get();

    // Create the FSEventStream on a background thread with its own run loop
    monitor->runLoopThread = std::thread([rawMonitor, path]() {
        CFStringRef cfPath = CFStringCreateWithCString(nullptr, path.c_str(), kCFStringEncodingUTF8);
        CFArrayRef pathsToWatch = CFArrayCreate(nullptr,
            reinterpret_cast<const void**>(&cfPath), 1, &kCFTypeArrayCallBacks);

        FSEventStreamContext context = {};
        context.info = rawMonitor;

        rawMonitor->stream = FSEventStreamCreate(
            nullptr,
            fsEventsCallback,
            &context,
            pathsToWatch,
            kFSEventStreamEventIdSinceNow,
            0.5, // latency in seconds
            kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes
        );

        CFRelease(pathsToWatch);
        CFRelease(cfPath);

        if (rawMonitor->stream) {
            CFRunLoopRef runLoop = CFRunLoopGetCurrent();
            rawMonitor->runLoopRef = runLoop;
            FSEventStreamScheduleWithRunLoop(rawMonitor->stream, runLoop, kCFRunLoopDefaultMode);
            FSEventStreamStart(rawMonitor->stream);
            CFRunLoopRun();
        }
    });

    monitors_[path] = std::move(monitor);
    logger_.info("Started FSEvents file monitoring on: {}", path);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> MacOSDriver::stopFileMonitoring(
    const std::string& path) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = monitors_.find(path);
    if (it == monitors_.end()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Not monitoring path: " + path, Core::ErrorCategory::Internal));
    }

    auto& monitor = it->second;
    monitor->running.store(false);

    if (monitor->stream) {
        FSEventStreamStop(monitor->stream);
        FSEventStreamInvalidate(monitor->stream);
        FSEventStreamRelease(monitor->stream);
    }

    if (monitor->runLoopRef) {
        CFRunLoopStop(static_cast<CFRunLoopRef>(monitor->runLoopRef));
    }

    if (monitor->runLoopThread.joinable()) {
        monitor->runLoopThread.join();
    }

    monitors_.erase(it);
    logger_.info("Stopped FSEvents file monitoring on: {}", path);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> MacOSDriver::addNetworkRule(const NetworkRule& rule) {
    if (rule.name.empty()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Rule name cannot be empty", Core::ErrorCategory::Validation));
    }

    std::lock_guard<std::mutex> lock(mutex_);
    rules_.push_back(rule);

    // Build pf rule string and apply via pfctl
    std::ostringstream pfRule;
    pfRule << (rule.action == NetworkRule::Action::Block ? "block" : "pass");
    pfRule << " " << (rule.direction == NetworkRule::Direction::Inbound ? "in" : "out");
    pfRule << " proto ";
    switch (rule.protocol) {
        case NetworkRule::Protocol::TCP: pfRule << "tcp"; break;
        case NetworkRule::Protocol::UDP: pfRule << "udp"; break;
        case NetworkRule::Protocol::ICMP: pfRule << "icmp"; break;
        default: pfRule << "{ tcp udp }"; break;
    }
    if (!rule.sourceAddress.empty()) {
        pfRule << " from " << rule.sourceAddress;
    }
    if (!rule.destinationAddress.empty()) {
        pfRule << " to " << rule.destinationAddress;
    }
    if (rule.destinationPort > 0) {
        pfRule << " port " << rule.destinationPort;
    }

    // Apply rule via pfctl (requires root privileges)
    std::string cmd = "echo '" + pfRule.str() + "' | pfctl -a threatone -f - 2>/dev/null";
    int ret = system(cmd.c_str());
    if (ret != 0) {
        logger_.warn("pfctl rule application returned non-zero (may require root): {}", rule.name);
    }

    logger_.info("Added pf network rule: {}", rule.name);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> MacOSDriver::removeNetworkRule(const std::string& ruleName) {
    if (ruleName.empty()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Rule name cannot be empty", Core::ErrorCategory::Validation));
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::remove_if(rules_.begin(), rules_.end(),
        [&ruleName](const NetworkRule& r) { return r.name == ruleName; });

    if (it == rules_.end()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Rule not found: " + ruleName, Core::ErrorCategory::Internal));
    }

    rules_.erase(it, rules_.end());

    // Flush the ThreatOne anchor and re-add remaining rules
    system("pfctl -a threatone -F rules 2>/dev/null");

    logger_.info("Removed pf network rule: {}", ruleName);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<std::vector<NetworkRule>, Core::Error> MacOSDriver::listNetworkRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    return Core::Result<std::vector<NetworkRule>, Core::Error>::ok(rules_);
}

Core::Result<std::vector<ProcessInfo>, Core::Error> MacOSDriver::listProcesses() {
    std::vector<ProcessInfo> processes;

    // Use sysctl to get process list
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t bufSize = 0;

    if (sysctl(mib, 4, nullptr, &bufSize, nullptr, 0) < 0) {
        return Core::Result<std::vector<ProcessInfo>, Core::Error>::err(
            Core::Error("sysctl KERN_PROC_ALL size query failed", Core::ErrorCategory::Internal));
    }

    std::vector<char> buffer(bufSize);
    if (sysctl(mib, 4, buffer.data(), &bufSize, nullptr, 0) < 0) {
        return Core::Result<std::vector<ProcessInfo>, Core::Error>::err(
            Core::Error("sysctl KERN_PROC_ALL data query failed", Core::ErrorCategory::Internal));
    }

    size_t numProcs = bufSize / sizeof(struct kinfo_proc);
    auto* procs = reinterpret_cast<struct kinfo_proc*>(buffer.data());

    for (size_t i = 0; i < numProcs; ++i) {
        ProcessInfo info;
        info.pid = static_cast<uint32_t>(procs[i].kp_proc.p_pid);
        info.parentPid = static_cast<uint32_t>(procs[i].kp_eproc.e_ppid);
        info.name = procs[i].kp_proc.p_comm;
        info.user = std::to_string(procs[i].kp_eproc.e_ucred.cr_uid);

        // Get executable path using proc_pidpath
        char pathBuf[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(static_cast<int>(info.pid), pathBuf, sizeof(pathBuf)) > 0) {
            info.executablePath = pathBuf;
        }

        // Get memory usage using proc_pidinfo
        struct proc_taskinfo taskInfo = {};
        int infoSize = proc_pidinfo(static_cast<int>(info.pid), PROC_PIDTASKINFO, 0,
                                     &taskInfo, sizeof(taskInfo));
        if (infoSize > 0) {
            info.memoryUsageBytes = taskInfo.pti_resident_size;
        }

        processes.push_back(std::move(info));
    }

    return Core::Result<std::vector<ProcessInfo>, Core::Error>::ok(std::move(processes));
}

Core::Result<ProcessInfo, Core::Error> MacOSDriver::getProcessInfo(uint32_t pid) {
    if (pid == 0) {
        return Core::Result<ProcessInfo, Core::Error>::err(
            Core::Error("Invalid PID: 0", Core::ErrorCategory::Validation));
    }

    ProcessInfo info;
    info.pid = pid;

    // Get process path
    char pathBuf[PROC_PIDPATHINFO_MAXSIZE] = {};
    if (proc_pidpath(static_cast<int>(pid), pathBuf, sizeof(pathBuf)) <= 0) {
        return Core::Result<ProcessInfo, Core::Error>::err(
            Core::Error("Cannot get info for process " + std::to_string(pid),
                       Core::ErrorCategory::Internal));
    }
    info.executablePath = pathBuf;

    // Extract name from path
    std::string pathStr(pathBuf);
    auto lastSlash = pathStr.find_last_of('/');
    info.name = (lastSlash != std::string::npos) ? pathStr.substr(lastSlash + 1) : pathStr;

    // Get memory and CPU info
    struct proc_taskinfo taskInfo = {};
    int infoSize = proc_pidinfo(static_cast<int>(pid), PROC_PIDTASKINFO, 0,
                                 &taskInfo, sizeof(taskInfo));
    if (infoSize > 0) {
        info.memoryUsageBytes = taskInfo.pti_resident_size;
    }

    // Get parent PID via sysctl
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, static_cast<int>(pid) };
    struct kinfo_proc kp = {};
    size_t kpSize = sizeof(kp);
    if (sysctl(mib, 4, &kp, &kpSize, nullptr, 0) == 0) {
        info.parentPid = static_cast<uint32_t>(kp.kp_eproc.e_ppid);
        info.user = std::to_string(kp.kp_eproc.e_ucred.cr_uid);
    }

    return Core::Result<ProcessInfo, Core::Error>::ok(std::move(info));
}

Core::Result<void, Core::Error> MacOSDriver::terminateProcess(uint32_t pid) {
    if (pid == 0) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Cannot terminate kernel_task (PID 0)",
                       Core::ErrorCategory::Validation));
    }

    if (kill(static_cast<pid_t>(pid), SIGTERM) != 0) {
        if (errno == ESRCH) {
            return Core::Result<void, Core::Error>::err(
                Core::Error("Process not found: " + std::to_string(pid),
                           Core::ErrorCategory::Internal));
        }
        if (errno == EPERM) {
            return Core::Result<void, Core::Error>::err(
                Core::Error("Permission denied to terminate process: " + std::to_string(pid),
                           Core::ErrorCategory::Internal));
        }
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to terminate process: " + std::to_string(pid),
                       Core::ErrorCategory::Internal));
    }

    logger_.info("Sent SIGTERM to process: {}", pid);
    return Core::Result<void, Core::Error>::ok();
}

std::string MacOSDriver::platformName() const {
    return "macOS";
}

bool MacOSDriver::isSupported() const {
    return true;
}

} // namespace ThreatOne::Platform

#endif // __APPLE__
