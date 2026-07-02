#pragma once

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include "edr/IEDREngine.h"
#include "core/Logger.h"
#include <cstdint>

namespace ThreatOne::EDR {

// Suspicion score and details for command-line analysis
struct CommandLineAnalysis {
    double score = 0.0; // 0.0 (benign) to 1.0 (highly suspicious)
    std::vector<std::string> indicators;
};

// Threat indicators for suspicious process trees
struct ProcessTreeIndicator {
    std::string type; // "deep_nesting", "orphan", "unusual_parent"
    std::string description;
    uint64_t pid = 0;
    double severity = 0.0; // 0.0 to 1.0
};

// Callback types for process events
using ProcessCreationCallback = std::function<void(const ProcessInfo&)>;
using ProcessTerminationCallback = std::function<void(uint64_t pid)>;

class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor() = default;

    // Enumerate all running processes
    [[nodiscard]] std::vector<ProcessInfo> enumerateProcesses() const;

    // Register callbacks for process events
    void onProcessCreation(ProcessCreationCallback callback);
    void onProcessTermination(ProcessTerminationCallback callback);

    // Detect suspicious process tree starting from a given PID
    [[nodiscard]] std::vector<ProcessTreeIndicator> detectSuspiciousProcessTree(uint64_t pid) const;

    // Analyze a command line for suspicious patterns
    [[nodiscard]] CommandLineAnalysis analyzeCommandLine(const std::string& cmdLine) const;

    // Polling method to detect changes (call periodically)
    void poll();

    // Allow injecting mock process data for testing
    void setMockProcessData(std::vector<ProcessInfo> mockData);
    void clearMockProcessData();

private:
    [[nodiscard]] std::vector<ProcessInfo> readProcFilesystem() const;
    [[nodiscard]] ProcessInfo readProcessInfo(uint64_t pid) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    // Callbacks
    std::vector<ProcessCreationCallback> creationCallbacks_;
    std::vector<ProcessTerminationCallback> terminationCallbacks_;

    // Previous snapshot for change detection
    std::unordered_set<uint64_t> previousPids_;

    // Mock data for testing
    bool useMockData_ = false;
    std::vector<ProcessInfo> mockData_;
};

} // namespace ThreatOne::EDR
