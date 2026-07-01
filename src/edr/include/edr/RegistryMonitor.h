#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <filesystem>
#include <chrono>

#include "edr/IEDREngine.h"
#include "core/Logger.h"

namespace ThreatOne::EDR {

// Persistence mechanism detection result
struct PersistenceMechanism {
    std::string type; // "cron", "systemd", "shell_profile", "ld_preload", "passwd"
    std::string location;
    std::string description;
    std::string severity; // "low", "medium", "high", "critical"
};

class RegistryMonitor {
public:
    explicit RegistryMonitor(size_t ringBufferSize = 1024);
    ~RegistryMonitor() = default;

    // Watch a specific config path for changes
    void watchConfigPath(const std::filesystem::path& path);

    // Get collected registry events
    [[nodiscard]] std::vector<RegistryEvent> getEvents() const;

    // Detect persistence mechanisms
    [[nodiscard]] std::vector<PersistenceMechanism> detectPersistenceMechanisms() const;

    // Poll for changes (call periodically)
    void poll();

    // Initialize with default system paths
    void watchDefaultPaths();

    // Clear event buffer
    void clearEvents();

private:
    struct ConfigFileState {
        std::filesystem::path path;
        std::filesystem::file_time_type lastModified;
        std::string contentHash;
        bool exists = false;
    };

    void checkFile(ConfigFileState& state);
    void addEvent(RegistryEvent event);
    [[nodiscard]] std::string computeSimpleHash(const std::filesystem::path& path) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    std::vector<ConfigFileState> watchedFiles_;

    // Ring buffer for events
    std::vector<RegistryEvent> eventBuffer_;
    size_t bufferHead_ = 0;
    size_t bufferCount_ = 0;
    size_t bufferCapacity_;
};

} // namespace ThreatOne::EDR
