#pragma once
#include <optional>

#include "sandbox/ISandboxEngine.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Sandbox {

enum class ResourceLimitType {
    CpuTime,
    Memory,
    FileDescriptors,
    DiskSpace,
    NetworkBandwidth
};

struct ResourceLimit {
    ResourceLimitType type = ResourceLimitType::Memory;
    uint64_t softLimit = 0;
    uint64_t hardLimit = 0;
    std::string unit;
};

struct FilesystemRestriction {
    std::string path;
    bool readable = false;
    bool writable = false;
    bool executable = false;
};

struct NetworkRestriction {
    bool allowOutbound = false;
    bool allowInbound = false;
    std::vector<std::string> allowedHosts;
    std::vector<int> allowedPorts;
};

enum class ProcessState {
    Created,
    Running,
    Suspended,
    Terminated,
    TimedOut
};

struct SandboxedProcess {
    std::string id;
    std::string executablePath;
    std::vector<std::string> arguments;
    ProcessState state = ProcessState::Created;
    int exitCode = -1;
    uint64_t cpuTimeMs = 0;
    uint64_t memoryUsedBytes = 0;
    std::string startedAt;
    std::string terminatedAt;
    std::vector<ResourceLimit> limits;
    std::vector<FilesystemRestriction> fsRestrictions;
    NetworkRestriction netRestriction;
};

class ProcessSandbox {
public:
    ProcessSandbox();
    ~ProcessSandbox() = default;

    // Process lifecycle
    std::string createProcess(const std::string& executablePath,
                              const std::vector<std::string>& arguments);
    bool startProcess(const std::string& processId);
    bool suspendProcess(const std::string& processId);
    bool resumeProcess(const std::string& processId);
    bool terminateProcess(const std::string& processId, int exitCode = 0);

    // Resource limits
    bool setResourceLimit(const std::string& processId, const ResourceLimit& limit);
    [[nodiscard]] std::vector<ResourceLimit> getResourceLimits(const std::string& processId) const;
    bool checkResourceViolation(const std::string& processId) const;

    // Filesystem restrictions
    bool addFilesystemRestriction(const std::string& processId, const FilesystemRestriction& restriction);
    [[nodiscard]] std::vector<FilesystemRestriction> getFilesystemRestrictions(const std::string& processId) const;
    bool isPathAllowed(const std::string& processId, const std::string& path, bool write) const;

    // Network control
    bool setNetworkRestriction(const std::string& processId, const NetworkRestriction& restriction);
    [[nodiscard]] NetworkRestriction getNetworkRestriction(const std::string& processId) const;
    bool isNetworkAllowed(const std::string& processId, const std::string& host, int port) const;

    // Process info
    [[nodiscard]] std::vector<SandboxedProcess> getActiveProcesses() const;
    [[nodiscard]] std::optional<SandboxedProcess> getProcess(const std::string& processId) const;
    [[nodiscard]] uint64_t getActiveProcessCount() const;

    // Timeout handling
    bool setProcessTimeout(const std::string& processId, uint64_t timeoutMs);
    bool timeoutProcess(const std::string& processId);

private:
    std::string generateProcessId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, SandboxedProcess> processes_;
    std::unordered_map<std::string, uint64_t> timeouts_; // processId -> timeout ms
    int nextProcessId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Sandbox
