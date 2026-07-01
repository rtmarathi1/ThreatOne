#pragma once

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <filesystem>
#include <chrono>

#include "edr/IEDREngine.h"
#include "core/Logger.h"

namespace ThreatOne::EDR {

// Suspicious file operation indicator
struct SuspiciousFileIndicator {
    std::string type; // "mass_create", "executable_drop", "hidden_file", "permission_change"
    std::string description;
    double severity = 0.0;
    std::vector<std::string> affectedPaths;
};

// Callback for real-time notification
using FileEventCallback = std::function<void(const FileEvent&)>;

class FileMonitor {
public:
    explicit FileMonitor(size_t ringBufferSize = 1024);
    ~FileMonitor() = default;

    // Watch/unwatch directories
    void watchDirectory(const std::filesystem::path& path, bool recursive = false);
    void unwatchDirectory(const std::filesystem::path& path);

    // Get collected events
    [[nodiscard]] std::vector<FileEvent> getEvents() const;

    // Register callback for real-time notification
    void setCallback(FileEventCallback callback);

    // Poll for changes (call periodically)
    void poll();

    // Detect suspicious file operations based on recent events
    [[nodiscard]] std::vector<SuspiciousFileIndicator> detectSuspiciousOperations() const;

    // Clear event buffer
    void clearEvents();

private:
    struct WatchEntry {
        std::filesystem::path path;
        bool recursive = false;
        // File state: path -> last_write_time
        std::unordered_map<std::string, std::filesystem::file_time_type> fileStates;
    };

    void scanDirectory(WatchEntry& entry);
    void addEvent(FileEvent event);

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    std::vector<WatchEntry> watches_;
    FileEventCallback callback_;

    // Ring buffer for events
    std::vector<FileEvent> eventBuffer_;
    size_t bufferHead_ = 0;
    size_t bufferCount_ = 0;
    size_t bufferCapacity_;
};

} // namespace ThreatOne::EDR
