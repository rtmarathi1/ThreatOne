#pragma once

#include "plugin/IPluginManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>

namespace ThreatOne::Plugin {

struct PluginVersionInfo {
    std::string pluginId;
    std::string version;
    std::string previousVersion;
    std::string installedAt;
    bool active = false;
    std::string changelog;
};

struct MigrationResult {
    std::string pluginId;
    std::string fromVersion;
    std::string toVersion;
    bool success = false;
    std::string errorMessage;
};

class PluginVersionManager {
public:
    PluginVersionManager();
    ~PluginVersionManager() = default;

    // Version registration
    std::string registerVersion(const std::string& pluginId, const std::string& version, const std::string& changelog = "");
    [[nodiscard]] std::vector<PluginVersionInfo> getVersionHistory(const std::string& pluginId) const;
    [[nodiscard]] std::string getCurrentVersion(const std::string& pluginId) const;

    // Migration
    MigrationResult migrateToVersion(const std::string& pluginId, const std::string& targetVersion);
    [[nodiscard]] bool canMigrate(const std::string& pluginId, const std::string& targetVersion) const;

    // Rollback
    MigrationResult rollback(const std::string& pluginId);
    [[nodiscard]] bool canRollback(const std::string& pluginId) const;
    [[nodiscard]] std::string getPreviousVersion(const std::string& pluginId) const;

    // Version comparison
    [[nodiscard]] int compareVersions(const std::string& v1, const std::string& v2) const;
    [[nodiscard]] bool isNewerVersion(const std::string& current, const std::string& candidate) const;

    // Management
    bool removeVersionHistory(const std::string& pluginId);
    [[nodiscard]] size_t getTrackedPluginCount() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::vector<PluginVersionInfo>> versions_;  // pluginId -> version history
    std::map<std::string, std::string> currentVersions_;              // pluginId -> current version

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Plugin
