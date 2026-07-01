#pragma once

// ThreatOne Platform - IPlatformDriver
// Abstract interface for platform-specific system operations including
// file monitoring, network filtering, and process monitoring.

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

#include "core/Error.h"

namespace ThreatOne::Platform {

// Event types for file monitoring
enum class FileEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
    AttributeChanged
};

struct FileEvent {
    FileEventType type;
    std::string path;
    std::string oldPath; // For rename events
};

using FileEventCallback = std::function<void(const FileEvent&)>;

// Network filtering rule
struct NetworkRule {
    enum class Action { Allow, Block, Log };
    enum class Direction { Inbound, Outbound, Both };
    enum class Protocol { TCP, UDP, ICMP, Any };

    std::string name;
    Action action = Action::Block;
    Direction direction = Direction::Both;
    Protocol protocol = Protocol::Any;
    std::string sourceAddress;
    std::string destinationAddress;
    uint16_t sourcePort = 0;
    uint16_t destinationPort = 0;
    int priority = 0;
};

// Process information
struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t parentPid = 0;
    std::string name;
    std::string executablePath;
    std::string commandLine;
    std::string user;
    uint64_t memoryUsageBytes = 0;
    double cpuPercent = 0.0;
};

// Abstract platform driver interface
class IPlatformDriver {
public:
    virtual ~IPlatformDriver() = default;

    // File monitoring
    virtual Core::Result<void, Core::Error> startFileMonitoring(
        const std::string& path, FileEventCallback callback) = 0;
    virtual Core::Result<void, Core::Error> stopFileMonitoring(
        const std::string& path) = 0;

    // Network filtering
    virtual Core::Result<void, Core::Error> addNetworkRule(
        const NetworkRule& rule) = 0;
    virtual Core::Result<void, Core::Error> removeNetworkRule(
        const std::string& ruleName) = 0;
    virtual Core::Result<std::vector<NetworkRule>, Core::Error> listNetworkRules() = 0;

    // Process monitoring
    virtual Core::Result<std::vector<ProcessInfo>, Core::Error> listProcesses() = 0;
    virtual Core::Result<ProcessInfo, Core::Error> getProcessInfo(uint32_t pid) = 0;
    virtual Core::Result<void, Core::Error> terminateProcess(uint32_t pid) = 0;

    // Platform identification
    virtual std::string platformName() const = 0;
    virtual bool isSupported() const = 0;
};

} // namespace ThreatOne::Platform
