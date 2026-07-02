// ThreatOne Platform - LinuxDriver implementation
// Uses inotify, iptables, and /proc filesystem for platform operations.

#ifdef __linux__

#include "LinuxDriver.h"

#include <sys/inotify.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ThreatOne::Platform {

LinuxDriver::LinuxDriver()
    : logger_(Core::Logger::instance().getModuleLogger("Platform.Linux")) {
    logger_.info("Linux platform driver created");
}

LinuxDriver::~LinuxDriver() {
    running_ = false;
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
    if (inotifyFd_ >= 0) {
        close(inotifyFd_);
    }
}

Core::Result<void, Core::Error> LinuxDriver::startFileMonitoring(
    const std::string& path, FileEventCallback callback) {

    if (inotifyFd_ < 0) {
        inotifyFd_ = inotify_init1(IN_NONBLOCK);
        if (inotifyFd_ < 0) {
            return Core::Result<void, Core::Error>::err(
                Core::Error("Failed to initialize inotify: " + std::string(strerror(errno))));
        }
    }

    uint32_t mask = IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM |
                    IN_MOVED_TO | IN_ATTRIB;
    int wd = inotify_add_watch(inotifyFd_, path.c_str(), mask);
    if (wd < 0) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to add inotify watch for '" + path + "': " +
                       std::string(strerror(errno))));
    }

    WatchEntry entry;
    entry.watchDescriptor = wd;
    entry.path = path;
    entry.callback = std::move(callback);

    watches_[wd] = std::move(entry);
    pathToWd_[path] = wd;

    // Start monitoring thread if not already running
    if (!running_) {
        running_ = true;
        monitorThread_ = std::thread(&LinuxDriver::monitorLoop, this);
    }

    logger_.info("Started file monitoring for: {}", path);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> LinuxDriver::stopFileMonitoring(
    const std::string& path) {

    auto it = pathToWd_.find(path);
    if (it == pathToWd_.end()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("No watch found for path: " + path));
    }

    int wd = it->second;
    if (inotifyFd_ >= 0) {
        inotify_rm_watch(inotifyFd_, wd);
    }

    watches_.erase(wd);
    pathToWd_.erase(it);

    logger_.info("Stopped file monitoring for: {}", path);
    return Core::Result<void, Core::Error>::ok();
}

void LinuxDriver::monitorLoop() {
    constexpr size_t bufLen = 4096;
    std::array<char, bufLen> buffer{};

    while (running_) {
        ssize_t len = read(inotifyFd_, buffer.data(), bufLen);
        if (len <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }

        size_t offset = 0;
        while (offset < static_cast<size_t>(len)) {
            auto* event = reinterpret_cast<inotify_event*>(buffer.data() + offset);

            auto watchIt = watches_.find(event->wd);
            if (watchIt != watches_.end() && watchIt->second.callback) {
                FileEvent fileEvent;
                fileEvent.path = watchIt->second.path;
                if (event->len > 0) {
                    fileEvent.path += "/" + std::string(event->name);
                }

                if (event->mask & IN_CREATE) {
                    fileEvent.type = FileEventType::Created;
                } else if (event->mask & IN_MODIFY) {
                    fileEvent.type = FileEventType::Modified;
                } else if (event->mask & IN_DELETE) {
                    fileEvent.type = FileEventType::Deleted;
                } else if (event->mask & (IN_MOVED_FROM | IN_MOVED_TO)) {
                    fileEvent.type = FileEventType::Renamed;
                } else if (event->mask & IN_ATTRIB) {
                    fileEvent.type = FileEventType::AttributeChanged;
                }

                watchIt->second.callback(fileEvent);
            }

            offset += sizeof(inotify_event) + event->len;
        }
    }
}

std::string LinuxDriver::buildIptablesCommand(const NetworkRule& rule, bool remove) {
    std::ostringstream cmd;
    cmd << "/sbin/iptables";

    if (remove) {
        cmd << " -D";
    } else {
        cmd << " -A";
    }

    // Chain selection based on direction
    if (rule.direction == NetworkRule::Direction::Inbound) {
        cmd << " INPUT";
    } else if (rule.direction == NetworkRule::Direction::Outbound) {
        cmd << " OUTPUT";
    } else {
        cmd << " FORWARD";
    }

    // Protocol
    if (rule.protocol != NetworkRule::Protocol::Any) {
        cmd << " -p";
        switch (rule.protocol) {
            case NetworkRule::Protocol::TCP: cmd << " tcp"; break;
            case NetworkRule::Protocol::UDP: cmd << " udp"; break;
            case NetworkRule::Protocol::ICMP: cmd << " icmp"; break;
            default: break;
        }
    }

    // Source address
    if (!rule.sourceAddress.empty()) {
        cmd << " -s " << rule.sourceAddress;
    }

    // Destination address
    if (!rule.destinationAddress.empty()) {
        cmd << " -d " << rule.destinationAddress;
    }

    // Source port
    if (rule.sourcePort > 0 && rule.protocol != NetworkRule::Protocol::ICMP) {
        cmd << " --sport " << rule.sourcePort;
    }

    // Destination port
    if (rule.destinationPort > 0 && rule.protocol != NetworkRule::Protocol::ICMP) {
        cmd << " --dport " << rule.destinationPort;
    }

    // Action
    cmd << " -j";
    switch (rule.action) {
        case NetworkRule::Action::Allow: cmd << " ACCEPT"; break;
        case NetworkRule::Action::Block: cmd << " DROP"; break;
        case NetworkRule::Action::Log: cmd << " LOG"; break;
    }

    // Comment with rule name for identification
    cmd << " -m comment --comment \"threatone:" << rule.name << "\"";

    return cmd.str();
}

Core::Result<void, Core::Error> LinuxDriver::addNetworkRule(const NetworkRule& rule) {
    std::string cmd = buildIptablesCommand(rule, false);
    logger_.info("Adding network rule '{}': {}", rule.name, cmd);

#ifdef ENABLE_PLATFORM_DRIVERS
    int result = system(cmd.c_str());
    if (result != 0) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to add iptables rule '" + rule.name +
                       "' (exit code: " + std::to_string(result) + ")"));
    }
#else
    logger_.debug("Platform drivers disabled, skipping iptables command");
#endif

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> LinuxDriver::removeNetworkRule(const std::string& ruleName) {
    NetworkRule rule;
    rule.name = ruleName;
    std::string cmd = buildIptablesCommand(rule, true);
    logger_.info("Removing network rule '{}'", ruleName);

#ifdef ENABLE_PLATFORM_DRIVERS
    int result = system(cmd.c_str());
    if (result != 0) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to remove iptables rule '" + ruleName +
                       "' (exit code: " + std::to_string(result) + ")"));
    }
#else
    logger_.debug("Platform drivers disabled, skipping iptables command");
#endif

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<std::vector<NetworkRule>, Core::Error> LinuxDriver::listNetworkRules() {
    // In a full implementation, this would parse iptables -L output
    // For now, return empty list when drivers are not enabled
    std::vector<NetworkRule> rules;
    return Core::Result<std::vector<NetworkRule>, Core::Error>::ok(std::move(rules));
}

ProcessInfo LinuxDriver::readProcEntry(uint32_t pid) const {
    ProcessInfo info;
    info.pid = pid;

    std::string procPath = "/proc/" + std::to_string(pid);

    // Read command name from /proc/[pid]/comm
    {
        std::ifstream comm(procPath + "/comm");
        if (comm.is_open()) {
            std::getline(comm, info.name);
        }
    }

    // Read executable path from /proc/[pid]/exe symlink
    {
        std::array<char, 4096> linkBuf{};
        std::string exePath = procPath + "/exe";
        ssize_t len = readlink(exePath.c_str(), linkBuf.data(), linkBuf.size() - 1);
        if (len > 0) {
            linkBuf[static_cast<size_t>(len)] = '\0';
            info.executablePath = linkBuf.data();
        }
    }

    // Read command line from /proc/[pid]/cmdline
    {
        std::ifstream cmdline(procPath + "/cmdline");
        if (cmdline.is_open()) {
            std::string content;
            std::getline(cmdline, content, '\0');
            info.commandLine = content;
        }
    }

    // Read status for parent PID and memory
    {
        std::ifstream status(procPath + "/status");
        if (status.is_open()) {
            std::string line;
            while (std::getline(status, line)) {
                if (line.find("PPid:") == 0) {
                    info.parentPid = static_cast<uint32_t>(
                        std::stoul(line.substr(5)));
                } else if (line.find("VmRSS:") == 0) {
                    // Value is in kB
                    std::string val = line.substr(6);
                    info.memoryUsageBytes = std::stoull(val) * 1024;
                } else if (line.find("Uid:") == 0) {
                    // Just store the uid string for now
                    info.user = line.substr(4);
                }
            }
        }
    }

    return info;
}

Core::Result<std::vector<ProcessInfo>, Core::Error> LinuxDriver::listProcesses() {
    std::vector<ProcessInfo> processes;

    DIR* procDir = opendir("/proc");
    if (!procDir) {
        return Core::Result<std::vector<ProcessInfo>, Core::Error>::err(
            Core::Error("Failed to open /proc directory"));
    }

    struct dirent* entry;
    while ((entry = readdir(procDir)) != nullptr) {
        // Only look at numeric directory names (PIDs)
        if (entry->d_type != DT_DIR) continue;

        char* end = nullptr;
        unsigned long pid = strtoul(entry->d_name, &end, 10);
        if (*end != '\0') continue; // Not a numeric name

        processes.push_back(readProcEntry(static_cast<uint32_t>(pid)));
    }

    closedir(procDir);
    return Core::Result<std::vector<ProcessInfo>, Core::Error>::ok(std::move(processes));
}

Core::Result<ProcessInfo, Core::Error> LinuxDriver::getProcessInfo(uint32_t pid) {
    std::string procPath = "/proc/" + std::to_string(pid);
    if (!std::filesystem::exists(procPath)) {
        return Core::Result<ProcessInfo, Core::Error>::err(
            Core::Error("Process " + std::to_string(pid) + " not found"));
    }

    return Core::Result<ProcessInfo, Core::Error>::ok(readProcEntry(pid));
}

Core::Result<void, Core::Error> LinuxDriver::terminateProcess(uint32_t pid) {
    logger_.info("Terminating process {}", pid);

#ifdef ENABLE_PLATFORM_DRIVERS
    if (kill(static_cast<pid_t>(pid), SIGTERM) != 0) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to terminate process " + std::to_string(pid) +
                       ": " + std::string(strerror(errno))));
    }
#else
    logger_.debug("Platform drivers disabled, skipping process termination");
    (void)pid;
#endif

    return Core::Result<void, Core::Error>::ok();
}

std::string LinuxDriver::platformName() const {
    return "Linux";
}

bool LinuxDriver::isSupported() const {
    return true;
}

} // namespace ThreatOne::Platform

#endif // __linux__
