#pragma once

#include "plugin/IPluginManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <set>

namespace ThreatOne::Plugin {

struct PermissionAuditEntry {
    std::string pluginId;
    PluginPermission permission;
    bool granted = false;
    std::string timestamp;
};

class PluginPermissions {
public:
    PluginPermissions();
    ~PluginPermissions() = default;

    // Permission grants
    bool setPermissions(const std::string& pluginId, const std::vector<PluginPermission>& permissions);
    bool grantPermission(const std::string& pluginId, PluginPermission permission);
    bool revokePermission(const std::string& pluginId, PluginPermission permission);
    bool revokeAllPermissions(const std::string& pluginId);

    // Permission queries
    [[nodiscard]] std::vector<PluginPermission> getPermissions(const std::string& pluginId) const;
    [[nodiscard]] bool hasPermission(const std::string& pluginId, PluginPermission permission) const;
    [[nodiscard]] bool hasAnyPermissions(const std::string& pluginId) const;

    // Enforcement
    [[nodiscard]] bool checkAccess(const std::string& pluginId, PluginPermission requiredPermission) const;
    [[nodiscard]] std::vector<PluginPermission> getMissingPermissions(
        const std::string& pluginId, const std::vector<PluginPermission>& required) const;

    // Audit
    [[nodiscard]] std::vector<PermissionAuditEntry> getAuditLog() const;

    // Plugin registration
    bool registerPlugin(const std::string& pluginId);
    bool unregisterPlugin(const std::string& pluginId);
    [[nodiscard]] bool isRegistered(const std::string& pluginId) const;

    [[nodiscard]] size_t getRegisteredPluginCount() const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::set<PluginPermission>> permissions_;
    std::vector<PermissionAuditEntry> auditLog_;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Plugin
