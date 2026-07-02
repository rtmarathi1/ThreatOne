#include "plugin/PluginVersionManager.h"
#include <mutex>

#include <algorithm>
#include <sstream>

namespace ThreatOne::Plugin {

PluginVersionManager::PluginVersionManager()
    : logger_("PluginVersionManager") {
    logger_.info("PluginVersionManager initialized");
}

std::string PluginVersionManager::registerVersion(const std::string& pluginId, const std::string& version,
                                                    const std::string& changelog) {
    std::lock_guard<std::mutex> lock(mutex_);

    PluginVersionInfo info;
    info.pluginId = pluginId;
    info.version = version;
    info.installedAt = "now";
    info.active = true;
    info.changelog = changelog;

    // Set previous version if exists
    auto currentIt = currentVersions_.find(pluginId);
    if (currentIt != currentVersions_.end()) {
        info.previousVersion = currentIt->second;
    }

    // Deactivate previous versions
    auto& history = versions_[pluginId];
    for (auto& v : history) {
        v.active = false;
    }

    history.push_back(info);
    currentVersions_[pluginId] = version;

    logger_.info("Registered version {} for plugin {}", version, pluginId);
    return version;
}

std::vector<PluginVersionInfo> PluginVersionManager::getVersionHistory(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = versions_.find(pluginId);
    if (it == versions_.end()) {
        return {};
    }
    return it->second;
}

std::string PluginVersionManager::getCurrentVersion(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = currentVersions_.find(pluginId);
    if (it == currentVersions_.end()) {
        return "";
    }
    return it->second;
}

MigrationResult PluginVersionManager::migrateToVersion(const std::string& pluginId, const std::string& targetVersion) {
    std::lock_guard<std::mutex> lock(mutex_);

    MigrationResult result;
    result.pluginId = pluginId;
    result.toVersion = targetVersion;

    auto currentIt = currentVersions_.find(pluginId);
    if (currentIt == currentVersions_.end()) {
        result.success = false;
        result.errorMessage = "Plugin not tracked";
        return result;
    }

    result.fromVersion = currentIt->second;

    if (currentIt->second == targetVersion) {
        result.success = false;
        result.errorMessage = "Already at target version";
        return result;
    }

    // Check if target version exists in history
    auto histIt = versions_.find(pluginId);
    bool versionExists = false;
    if (histIt != versions_.end()) {
        for (const auto& v : histIt->second) {
            if (v.version == targetVersion) {
                versionExists = true;
                break;
            }
        }
    }

    if (!versionExists) {
        // Register new version
        PluginVersionInfo info;
        info.pluginId = pluginId;
        info.version = targetVersion;
        info.previousVersion = currentIt->second;
        info.installedAt = "now";
        info.active = true;

        auto& history = versions_[pluginId];
        for (auto& v : history) {
            v.active = false;
        }
        history.push_back(info);
    } else {
        // Activate existing version
        auto& history = versions_[pluginId];
        for (auto& v : history) {
            v.active = (v.version == targetVersion);
        }
    }

    currentVersions_[pluginId] = targetVersion;
    result.success = true;
    logger_.info("Migrated plugin {} from {} to {}", pluginId, result.fromVersion, targetVersion);
    return result;
}

bool PluginVersionManager::canMigrate(const std::string& pluginId, const std::string& targetVersion) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto currentIt = currentVersions_.find(pluginId);
    if (currentIt == currentVersions_.end()) {
        return false;
    }
    return currentIt->second != targetVersion;
}

MigrationResult PluginVersionManager::rollback(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    MigrationResult result;
    result.pluginId = pluginId;

    auto histIt = versions_.find(pluginId);
    if (histIt == versions_.end() || histIt->second.size() < 2) {
        result.success = false;
        result.errorMessage = "No previous version to rollback to";
        return result;
    }

    auto& history = histIt->second;
    auto currentIt = currentVersions_.find(pluginId);
    result.fromVersion = currentIt->second;

    // Find the active version and roll back to previous
    std::string previousVersion;
    for (size_t idx = history.size(); idx > 0; --idx) {
        size_t i = idx - 1;
        if (history[i].active) {
            if (!history[i].previousVersion.empty()) {
                previousVersion = history[i].previousVersion;
            } else if (i > 0) {
                previousVersion = history[i - 1].version;
            }
            break;
        }
    }

    if (previousVersion.empty()) {
        result.success = false;
        result.errorMessage = "No previous version found";
        return result;
    }

    result.toVersion = previousVersion;

    // Update active flags
    for (auto& v : history) {
        v.active = (v.version == previousVersion);
    }

    currentVersions_[pluginId] = previousVersion;
    result.success = true;
    logger_.info("Rolled back plugin {} from {} to {}", pluginId, result.fromVersion, previousVersion);
    return result;
}

bool PluginVersionManager::canRollback(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = versions_.find(pluginId);
    if (it == versions_.end()) {
        return false;
    }
    return it->second.size() >= 2;
}

std::string PluginVersionManager::getPreviousVersion(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = versions_.find(pluginId);
    if (it == versions_.end() || it->second.empty()) {
        return "";
    }

    const auto& history = it->second;
    for (size_t idx = history.size(); idx > 0; --idx) {
        size_t i = idx - 1;
        if (history[i].active && !history[i].previousVersion.empty()) {
            return history[i].previousVersion;
        }
    }

    if (history.size() >= 2) {
        return history[history.size() - 2].version;
    }
    return "";
}

int PluginVersionManager::compareVersions(const std::string& v1, const std::string& v2) const {
    auto parse = [](const std::string& v) -> std::vector<int> {
        std::vector<int> parts;
        std::istringstream ss(v);
        std::string token;
        while (std::getline(ss, token, '.')) {
            try {
                parts.push_back(std::stoi(token));
            } catch (...) {
                parts.push_back(0);
            }
        }
        return parts;
    };

    auto parts1 = parse(v1);
    auto parts2 = parse(v2);

    size_t maxLen = std::max(parts1.size(), parts2.size());
    parts1.resize(maxLen, 0);
    parts2.resize(maxLen, 0);

    for (size_t i = 0; i < maxLen; ++i) {
        if (parts1[i] < parts2[i]) return -1;
        if (parts1[i] > parts2[i]) return 1;
    }
    return 0;
}

bool PluginVersionManager::isNewerVersion(const std::string& current, const std::string& candidate) const {
    return compareVersions(candidate, current) > 0;
}

bool PluginVersionManager::removeVersionHistory(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    bool found = versions_.erase(pluginId) > 0;
    found = (currentVersions_.erase(pluginId) > 0) || found;
    if (found) {
        logger_.info("Removed version history for plugin: {}", pluginId);
    }
    return found;
}

size_t PluginVersionManager::getTrackedPluginCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return currentVersions_.size();
}

} // namespace ThreatOne::Plugin
