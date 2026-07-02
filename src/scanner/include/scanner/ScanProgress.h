#pragma once

// ThreatOne Scanner - Scan Progress Tracker
// Thread-safe progress tracking with atomics for lock-free reads

#include <string>
#include <atomic>
#include <mutex>
#include <chrono>

#include <core/Logger.h>
#include <cstdint>

namespace ThreatOne::Scanner {

// Progress state snapshot
struct ProgressSnapshot {
    uint64_t totalFiles = 0;
    uint64_t filesScanned = 0;
    uint64_t threatsFound = 0;
    uint64_t bytesScanned = 0;
    double percentage = 0.0;
    double etaSeconds = 0.0;
    std::string currentFile;
    std::chrono::steady_clock::time_point startTime;
    double elapsedSeconds = 0.0;
};

// Thread-safe progress tracker
class ScanProgress {
public:
    ScanProgress();

    // Initialize with total file count
    void reset(uint64_t totalFiles);

    // Update progress (thread-safe)
    void incrementScanned();
    void incrementThreats();
    void addBytes(uint64_t bytes);
    void setCurrentFile(const std::string& file);

    // Read progress (lock-free for most fields)
    uint64_t totalFiles() const;
    uint64_t filesScanned() const;
    uint64_t threatsFound() const;
    uint64_t bytesScanned() const;
    double percentage() const;
    double etaSeconds() const;
    std::string currentFile() const;
    double elapsedSeconds() const;

    // Get a complete snapshot
    ProgressSnapshot snapshot() const;

    // Check if scan is complete
    bool isComplete() const;

private:
    std::atomic<uint64_t> totalFiles_;
    std::atomic<uint64_t> filesScanned_;
    std::atomic<uint64_t> threatsFound_;
    std::atomic<uint64_t> bytesScanned_;
    std::chrono::steady_clock::time_point startTime_;

    mutable std::mutex currentFileMutex_;
    std::string currentFile_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Scanner
