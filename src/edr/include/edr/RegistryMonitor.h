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
    RegistryMonitor();
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
    [[nodiscard]] std::string computeSimpleHash(const std::filesystem::path& path) const;

    mutable std::mutex mutex_;
    Core::ModuleLogger logger_;

    std::vector<ConfigFileState> watchedFiles_;
    std::vector<RegistryEvent> events_;
};

} // namespace ThreatOne::EDR
