#include "edr/ProcessMonitor.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ThreatOne::EDR {

ProcessMonitor::ProcessMonitor()
    : logger_(Core::Logger::instance().getModuleLogger("ProcessMonitor")) {
    logger_.info("ProcessMonitor initialized");
}

std::vector<ProcessInfo> ProcessMonitor::enumerateProcesses() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (useMockData_) {
        return mockData_;
    }

    return readProcFilesystem();
}

void ProcessMonitor::onProcessCreation(ProcessCreationCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    creationCallbacks_.push_back(std::move(callback));
}

void ProcessMonitor::onProcessTermination(ProcessTerminationCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    terminationCallbacks_.push_back(std::move(callback));
}

std::vector<ProcessTreeIndicator> ProcessMonitor::detectSuspiciousProcessTree(uint64_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ProcessTreeIndicator> indicators;
    std::vector<ProcessInfo> processes;

    if (useMockData_) {
        processes = mockData_;
    } else {
        processes = readProcFilesystem();
    }

    // Build parent-child map
    std::unordered_map<uint64_t, std::vector<uint64_t>> childrenMap;
    std::unordered_map<uint64_t, uint64_t> parentMap;
    std::unordered_set<uint64_t> allPids;

    for (const auto& proc : processes) {
        childrenMap[proc.parentPid].push_back(proc.pid);
        parentMap[proc.pid] = proc.parentPid;
        allPids.insert(proc.pid);
    }

    // Check 1: Deep nesting (process tree depth > 5)
    uint64_t current = pid;
    int depth = 0;
    std::unordered_set<uint64_t> visited;
    while (current != 0 && current != 1 && depth < 20) {
        if (visited.count(current)) break;
        visited.insert(current);
        auto it = parentMap.find(current);
        if (it == parentMap.end()) break;
        current = it->second;
        depth++;
    }

    if (depth > 5) {
        ProcessTreeIndicator ind;
        ind.type = "deep_nesting";
        ind.description = "Process tree depth exceeds threshold (" + std::to_string(depth) + " levels)";
        ind.pid = pid;
        ind.severity = std::min(1.0, depth / 10.0);
        indicators.push_back(ind);
    }

    // Check 2: Orphaned process (parent doesn't exist but isn't init/0)
    auto parentIt = parentMap.find(pid);
    if (parentIt != parentMap.end()) {
        uint64_t ppid = parentIt->second;
        if (ppid != 0 && ppid != 1 && allPids.find(ppid) == allPids.end()) {
            ProcessTreeIndicator ind;
            ind.type = "orphan";
            ind.description = "Process is orphaned (parent PID " + std::to_string(ppid) + " does not exist)";
            ind.pid = pid;
            ind.severity = 0.4;
            indicators.push_back(ind);
        }
    }

    // Check 3: Unusual parent-child relationships
    // Detect if a non-shell process spawned a shell
    for (const auto& proc : processes) {
        if (proc.pid == pid) {
            // Check if this process is a shell spawned by a non-interactive parent
            bool isShell = (proc.name == "sh" || proc.name == "bash" ||
                           proc.name == "zsh" || proc.name == "dash");
            if (isShell) {
                // Look up parent
                for (const auto& parent : processes) {
                    if (parent.pid == proc.parentPid) {
                        bool parentIsShell = (parent.name == "sh" || parent.name == "bash" ||
                                            parent.name == "zsh" || parent.name == "dash" ||
                                            parent.name == "login" || parent.name == "sshd" ||
                                            parent.name == "tmux" || parent.name == "screen");
                        if (!parentIsShell && !parent.name.empty()) {
                            ProcessTreeIndicator ind;
                            ind.type = "unusual_parent";
                            ind.description = "Shell (" + proc.name + ") spawned by unusual parent (" + parent.name + ")";
                            ind.pid = pid;
                            ind.severity = 0.6;
                            indicators.push_back(ind);
                        }
                        break;
                    }
                }
            }
            break;
        }
    }

    return indicators;
}

CommandLineAnalysis ProcessMonitor::analyzeCommandLine(const std::string& cmdLine) const {
    CommandLineAnalysis result;
    result.score = 0.0;

    if (cmdLine.empty()) {
        return result;
    }

    // Check for base64 decode commands
    if (cmdLine.find("base64") != std::string::npos &&
        (cmdLine.find("-d") != std::string::npos || cmdLine.find("--decode") != std::string::npos)) {
        result.score += 0.3;
        result.indicators.push_back("Base64 decode operation detected");
    }

    // Check for pipe to shell patterns (curl|bash, wget|sh)
    if ((cmdLine.find("curl") != std::string::npos || cmdLine.find("wget") != std::string::npos) &&
        (cmdLine.find("|") != std::string::npos) &&
        (cmdLine.find("bash") != std::string::npos || cmdLine.find("sh") != std::string::npos)) {
        result.score += 0.5;
        result.indicators.push_back("Download-and-execute pattern (pipe to shell)");
    }

    // Check for known malicious tools
    static const std::vector<std::string> maliciousTools = {
        "mimikatz", "meterpreter", "cobaltstrike", "empire",
        "bloodhound", "rubeus", "lazagne", "crackmapexec",
        "ncat", "netcat", "nc.traditional"
    };

    std::string lower = cmdLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    for (const auto& tool : maliciousTools) {
        if (lower.find(tool) != std::string::npos) {
            result.score += 0.7;
            result.indicators.push_back("Known malicious tool detected: " + tool);
            break;
        }
    }

    // Check for suspicious PowerShell-like patterns
    if (lower.find("powershell") != std::string::npos ||
        lower.find("pwsh") != std::string::npos) {
        if (lower.find("-encodedcommand") != std::string::npos ||
            lower.find("-enc ") != std::string::npos ||
            lower.find("-nop") != std::string::npos ||
            lower.find("-windowstyle hidden") != std::string::npos) {
            result.score += 0.6;
            result.indicators.push_back("Suspicious PowerShell invocation with obfuscation flags");
        }
    }

    // Check for reverse shell patterns
    if ((lower.find("/dev/tcp/") != std::string::npos) ||
        (lower.find("nc ") != std::string::npos && lower.find("-e") != std::string::npos) ||
        (lower.find("bash -i") != std::string::npos && lower.find(">&") != std::string::npos)) {
        result.score += 0.8;
        result.indicators.push_back("Reverse shell pattern detected");
    }

    // Check for credential access patterns
    if (lower.find("/etc/shadow") != std::string::npos ||
        lower.find("/etc/passwd") != std::string::npos) {
        if (lower.find("cat") != std::string::npos || lower.find("cp") != std::string::npos) {
            result.score += 0.4;
            result.indicators.push_back("Credential file access detected");
        }
    }

    // Check for privilege escalation
    if (lower.find("chmod") != std::string::npos &&
        (lower.find("+s") != std::string::npos || lower.find("4755") != std::string::npos)) {
        result.score += 0.6;
        result.indicators.push_back("SUID bit manipulation detected");
    }

    // Cap score at 1.0
    result.score = std::min(1.0, result.score);

    return result;
}

void ProcessMonitor::poll() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ProcessInfo> current;
    if (useMockData_) {
        current = mockData_;
    } else {
        current = readProcFilesystem();
    }

    std::unordered_set<uint64_t> currentPids;
    for (const auto& proc : current) {
        currentPids.insert(proc.pid);
    }

    // Detect new processes
    for (const auto& proc : current) {
        if (previousPids_.find(proc.pid) == previousPids_.end()) {
            for (const auto& cb : creationCallbacks_) {
                cb(proc);
            }
        }
    }

    // Detect terminated processes
    for (uint64_t pid : previousPids_) {
        if (currentPids.find(pid) == currentPids.end()) {
            for (const auto& cb : terminationCallbacks_) {
                cb(pid);
            }
        }
    }

    previousPids_ = currentPids;
}

void ProcessMonitor::setMockProcessData(std::vector<ProcessInfo> mockData) {
    std::lock_guard<std::mutex> lock(mutex_);
    useMockData_ = true;
    mockData_ = std::move(mockData);
}

void ProcessMonitor::clearMockProcessData() {
    std::lock_guard<std::mutex> lock(mutex_);
    useMockData_ = false;
    mockData_.clear();
}

std::vector<ProcessInfo> ProcessMonitor::readProcFilesystem() const {
    std::vector<ProcessInfo> processes;
    namespace fs = std::filesystem;

    try {
        for (const auto& entry : fs::directory_iterator("/proc")) {
            if (!entry.is_directory()) continue;

            std::string dirName = entry.path().filename().string();

            // Check if directory name is numeric (PID)
            bool isNumeric = !dirName.empty() &&
                std::all_of(dirName.begin(), dirName.end(), ::isdigit);

            if (!isNumeric) continue;

            uint64_t pid = std::stoull(dirName);
            try {
                ProcessInfo info = readProcessInfo(pid);
                if (info.pid != 0) {
                    processes.push_back(std::move(info));
                }
            } catch (...) {
                // Process may have terminated between enumeration and read
                continue;
            }
        }
    } catch (const std::exception& e) {
        logger_.warn("Failed to read /proc filesystem: {}", e.what());
    }

    return processes;
}

ProcessInfo ProcessMonitor::readProcessInfo(uint64_t pid) const {
    ProcessInfo info;
    info.pid = pid;
    namespace fs = std::filesystem;

    std::string procPath = "/proc/" + std::to_string(pid);

    // Read process name from /proc/[pid]/comm
    {
        std::ifstream f(procPath + "/comm");
        if (f.is_open()) {
            std::getline(f, info.name);
        }
    }

    // Read command line from /proc/[pid]/cmdline
    {
        std::ifstream f(procPath + "/cmdline", std::ios::binary);
        if (f.is_open()) {
            std::ostringstream ss;
            char c;
            while (f.get(c)) {
                ss << (c == '\0' ? ' ' : c);
            }
            std::string fullCmdLine = ss.str();
            // Trim trailing space
            if (!fullCmdLine.empty() && fullCmdLine.back() == ' ') {
                fullCmdLine.pop_back();
            }
            info.commandLine = fullCmdLine;
        }
    }

    // Read exe path
    {
        try {
            info.path = fs::read_symlink(procPath + "/exe").string();
        } catch (...) {
            // Permission denied or no exe link
        }
    }

    // Read status for parent PID and user
    {
        std::ifstream f(procPath + "/status");
        if (f.is_open()) {
            std::string line;
            while (std::getline(f, line)) {
                if (line.compare(0, 5, "PPid:") == 0) {
                    info.parentPid = std::stoull(line.substr(6));
                } else if (line.compare(0, 4, "Uid:") == 0) {
                    // Extract real UID
                    std::istringstream iss(line.substr(5));
                    uint64_t uid;
                    if (iss >> uid) {
                        info.user = std::to_string(uid);
                    }
                }
            }
        }
    }

    return info;
}

} // namespace ThreatOne::EDR
