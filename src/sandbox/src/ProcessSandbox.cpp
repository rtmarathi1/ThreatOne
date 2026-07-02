#include "sandbox/ProcessSandbox.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace ThreatOne::Sandbox {

ProcessSandbox::ProcessSandbox()
    : logger_(Core::Logger::instance().getModuleLogger("ProcessSandbox")) {
    logger_.info("ProcessSandbox initialized");
}

std::string ProcessSandbox::generateProcessId() {
    return "PROC-" + std::to_string(nextProcessId_++);
}

std::string ProcessSandbox::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << time;
    return oss.str();
}

std::string ProcessSandbox::createProcess(const std::string& executablePath,
                                           const std::vector<std::string>& arguments) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (executablePath.empty()) {
        logger_.error("Cannot create process: empty executable path");
        return "";
    }

    std::string processId = generateProcessId();

    SandboxedProcess proc;
    proc.id = processId;
    proc.executablePath = executablePath;
    proc.arguments = arguments;
    proc.state = ProcessState::Created;
    proc.exitCode = -1;

    processes_[processId] = proc;
    logger_.info("Created sandboxed process: {} ({})", processId, executablePath);
    return processId;
}

bool ProcessSandbox::startProcess(const std::string& processId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        logger_.error("Cannot start: process {} not found", processId);
        return false;
    }

    if (it->second.state != ProcessState::Created &&
        it->second.state != ProcessState::Suspended) {
        logger_.error("Cannot start: process {} in invalid state", processId);
        return false;
    }

    it->second.state = ProcessState::Running;
    it->second.startedAt = getCurrentTimestamp();
    logger_.info("Started process: {}", processId);
    return true;
}

bool ProcessSandbox::suspendProcess(const std::string& processId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        logger_.error("Cannot suspend: process {} not found", processId);
        return false;
    }

    if (it->second.state != ProcessState::Running) {
        logger_.error("Cannot suspend: process {} not running", processId);
        return false;
    }

    it->second.state = ProcessState::Suspended;
    logger_.info("Suspended process: {}", processId);
    return true;
}

bool ProcessSandbox::resumeProcess(const std::string& processId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        logger_.error("Cannot resume: process {} not found", processId);
        return false;
    }

    if (it->second.state != ProcessState::Suspended) {
        logger_.error("Cannot resume: process {} not suspended", processId);
        return false;
    }

    it->second.state = ProcessState::Running;
    logger_.info("Resumed process: {}", processId);
    return true;
}

bool ProcessSandbox::terminateProcess(const std::string& processId, int exitCode) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        logger_.error("Cannot terminate: process {} not found", processId);
        return false;
    }

    if (it->second.state == ProcessState::Terminated ||
        it->second.state == ProcessState::TimedOut) {
        logger_.warn("Process {} already terminated", processId);
        return false;
    }

    it->second.state = ProcessState::Terminated;
    it->second.exitCode = exitCode;
    it->second.terminatedAt = getCurrentTimestamp();
    logger_.info("Terminated process: {} (exit code: {})", processId, exitCode);
    return true;
}

bool ProcessSandbox::setResourceLimit(const std::string& processId, const ResourceLimit& limit) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return false;
    }

    it->second.limits.push_back(limit);
    return true;
}

std::vector<ResourceLimit> ProcessSandbox::getResourceLimits(const std::string& processId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return {};
    }
    return it->second.limits;
}

bool ProcessSandbox::checkResourceViolation(const std::string& processId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return false;
    }

    for (const auto& limit : it->second.limits) {
        if (limit.type == ResourceLimitType::Memory) {
            if (it->second.memoryUsedBytes > limit.hardLimit && limit.hardLimit > 0) {
                return true;
            }
        }
        if (limit.type == ResourceLimitType::CpuTime) {
            if (it->second.cpuTimeMs > limit.hardLimit && limit.hardLimit > 0) {
                return true;
            }
        }
    }
    return false;
}

bool ProcessSandbox::addFilesystemRestriction(const std::string& processId,
                                               const FilesystemRestriction& restriction) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return false;
    }

    it->second.fsRestrictions.push_back(restriction);
    return true;
}

std::vector<FilesystemRestriction> ProcessSandbox::getFilesystemRestrictions(
    const std::string& processId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return {};
    }
    return it->second.fsRestrictions;
}

bool ProcessSandbox::isPathAllowed(const std::string& processId, const std::string& path,
                                    bool write) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return false;
    }

    if (it->second.fsRestrictions.empty()) {
        return true;  // No restrictions means all allowed
    }

    for (const auto& restriction : it->second.fsRestrictions) {
        if (path.find(restriction.path) == 0) {
            if (write) {
                return restriction.writable;
            }
            return restriction.readable;
        }
    }
    return false;  // Not in any allowed path
}

bool ProcessSandbox::setNetworkRestriction(const std::string& processId,
                                            const NetworkRestriction& restriction) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return false;
    }

    it->second.netRestriction = restriction;
    return true;
}

NetworkRestriction ProcessSandbox::getNetworkRestriction(const std::string& processId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return {};
    }
    return it->second.netRestriction;
}

bool ProcessSandbox::isNetworkAllowed(const std::string& processId, const std::string& host,
                                       int port) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return false;
    }

    const auto& restriction = it->second.netRestriction;
    if (!restriction.allowOutbound) {
        return false;
    }

    if (restriction.allowedHosts.empty() && restriction.allowedPorts.empty()) {
        return true;  // No specific restrictions
    }

    bool hostAllowed = restriction.allowedHosts.empty();
    for (const auto& allowed : restriction.allowedHosts) {
        if (host == allowed) {
            hostAllowed = true;
            break;
        }
    }

    bool portAllowed = restriction.allowedPorts.empty();
    for (int allowed : restriction.allowedPorts) {
        if (port == allowed) {
            portAllowed = true;
            break;
        }
    }

    return hostAllowed && portAllowed;
}

std::vector<SandboxedProcess> ProcessSandbox::getActiveProcesses() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<SandboxedProcess> active;
    for (const auto& [id, proc] : processes_) {
        if (proc.state == ProcessState::Running || proc.state == ProcessState::Suspended) {
            active.push_back(proc);
        }
    }
    return active;
}

std::optional<SandboxedProcess> ProcessSandbox::getProcess(const std::string& processId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return std::nullopt;
    }
    return it->second;
}

uint64_t ProcessSandbox::getActiveProcessCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t count = 0;
    for (const auto& [id, proc] : processes_) {
        if (proc.state == ProcessState::Running || proc.state == ProcessState::Suspended) {
            ++count;
        }
    }
    return count;
}

bool ProcessSandbox::setProcessTimeout(const std::string& processId, uint64_t timeoutMs) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return false;
    }
    timeouts_[processId] = timeoutMs;
    return true;
}

bool ProcessSandbox::timeoutProcess(const std::string& processId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processes_.find(processId);
    if (it == processes_.end()) {
        return false;
    }

    if (it->second.state == ProcessState::Terminated ||
        it->second.state == ProcessState::TimedOut) {
        return false;
    }

    it->second.state = ProcessState::TimedOut;
    it->second.terminatedAt = getCurrentTimestamp();
    logger_.info("Process {} timed out", processId);
    return true;
}

} // namespace ThreatOne::Sandbox
