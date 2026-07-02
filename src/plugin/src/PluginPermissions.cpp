#include "plugin/PluginPermissions.h"

#include <algorithm>

namespace ThreatOne::Plugin {

PluginPermissions::PluginPermissions()
    : logger_("PluginPermissions") {
    logger_.info("PluginPermissions initialized");
}

bool PluginPermissions::setPermissions(const std::string& pluginId, const std::vector<PluginPermission>& permissions) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Plugin must be registered
    if (permissions_.count(pluginId) == 0) {
        logger_.error("setPermissions: plugin {} not registered", pluginId);
        return false;
    }

    permissions_[pluginId] = std::set<PluginPermission>(permissions.begin(), permissions.end());

    PermissionAuditEntry entry;
    entry.pluginId = pluginId;
    entry.granted = true;
    entry.timestamp = "now";
    auditLog_.push_back(entry);

    logger_.info("Set {} permissions for plugin {}", permissions.size(), pluginId);
    return true;
}

bool PluginPermissions::grantPermission(const std::string& pluginId, PluginPermission permission) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (permissions_.count(pluginId) == 0) {
        logger_.error("grantPermission: plugin {} not registered", pluginId);
        return false;
    }

    permissions_[pluginId].insert(permission);

    PermissionAuditEntry entry;
    entry.pluginId = pluginId;
    entry.permission = permission;
    entry.granted = true;
    entry.timestamp = "now";
    auditLog_.push_back(entry);

    logger_.info("Granted permission to plugin {}", pluginId);
    return true;
}

bool PluginPermissions::revokePermission(const std::string& pluginId, PluginPermission permission) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = permissions_.find(pluginId);
    if (it == permissions_.end()) {
        return false;
    }

    it->second.erase(permission);

    PermissionAuditEntry entry;
    entry.pluginId = pluginId;
    entry.permission = permission;
    entry.granted = false;
    entry.timestamp = "now";
    auditLog_.push_back(entry);

    logger_.info("Revoked permission from plugin {}", pluginId);
    return true;
}

bool PluginPermissions::revokeAllPermissions(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = permissions_.find(pluginId);
    if (it == permissions_.end()) {
        return false;
    }

    it->second.clear();
    logger_.info("Revoked all permissions from plugin {}", pluginId);
    return true;
}

std::vector<PluginPermission> PluginPermissions::getPermissions(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = permissions_.find(pluginId);
    if (it == permissions_.end()) {
        return {};
    }
    return std::vector<PluginPermission>(it->second.begin(), it->second.end());
}

bool PluginPermissions::hasPermission(const std::string& pluginId, PluginPermission permission) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = permissions_.find(pluginId);
    if (it == permissions_.end()) {
        return false;
    }
    return it->second.count(permission) > 0;
}

bool PluginPermissions::hasAnyPermissions(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = permissions_.find(pluginId);
    if (it == permissions_.end()) {
        return false;
    }
    return !it->second.empty();
}

bool PluginPermissions::checkAccess(const std::string& pluginId, PluginPermission requiredPermission) const {
    return hasPermission(pluginId, requiredPermission);
}

std::vector<PluginPermission> PluginPermissions::getMissingPermissions(
    const std::string& pluginId, const std::vector<PluginPermission>& required) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PluginPermission> missing;
    auto it = permissions_.find(pluginId);
    if (it == permissions_.end()) {
        return required;
    }

    for (const auto& perm : required) {
        if (it->second.count(perm) == 0) {
            missing.push_back(perm);
        }
    }
    return missing;
}

std::vector<PermissionAuditEntry> PluginPermissions::getAuditLog() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return auditLog_;
}

bool PluginPermissions::registerPlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (permissions_.count(pluginId) > 0) {
        return false;  // Already registered
    }

    permissions_[pluginId] = {};
    logger_.info("Registered plugin for permissions: {}", pluginId);
    return true;
}

bool PluginPermissions::unregisterPlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = permissions_.find(pluginId);
    if (it == permissions_.end()) {
        return false;
    }

    permissions_.erase(it);
    logger_.info("Unregistered plugin from permissions: {}", pluginId);
    return true;
}

bool PluginPermissions::isRegistered(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return permissions_.count(pluginId) > 0;
}

size_t PluginPermissions::getRegisteredPluginCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return permissions_.size();
}

} // namespace ThreatOne::Plugin
