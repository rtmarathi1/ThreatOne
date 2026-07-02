#include "identity/RBACManager.h"
#include <string>
#include <vector>

namespace ThreatOne::Identity {

RBACManager::RBACManager() {
    // Initialize default roles
    addRole("admin", "Administrator", Role::Admin);
    addRole("analyst", "Security Analyst", Role::Analyst);
    addRole("viewer", "Read-Only Viewer", Role::Viewer);

    // Admin gets all permissions by default (wildcard handled in checkPermission)
    addPermissionToRole("admin", {"*", PermissionType::Read});
    addPermissionToRole("admin", {"*", PermissionType::Write});
    addPermissionToRole("admin", {"*", PermissionType::Execute});

    // Analyst gets read + execute
    addPermissionToRole("analyst", {"*", PermissionType::Read});
    addPermissionToRole("analyst", {"*", PermissionType::Execute});

    // Viewer gets read only
    addPermissionToRole("viewer", {"*", PermissionType::Read});
}

bool RBACManager::addRole(const std::string& roleId, const std::string& name, Role type) {
    if (roles_.contains(roleId)) {
        return false;
    }
    roles_[roleId] = RoleDefinition{roleId, name, type, {}};
    return true;
}

bool RBACManager::removeRole(const std::string& roleId) {
    if (!roles_.contains(roleId)) {
        return false;
    }
    roles_.erase(roleId);
    // Remove this role from all users
    for (auto& [userId, userRoleSet] : userRoles_) {
        userRoleSet.erase(roleId);
    }
    return true;
}

bool RBACManager::roleExists(const std::string& roleId) const {
    return roles_.contains(roleId);
}

bool RBACManager::addPermissionToRole(const std::string& roleId, const Permission& permission) {
    auto it = roles_.find(roleId);
    if (it == roles_.end()) {
        return false;
    }
    it->second.permissions.insert(permission);
    return true;
}

bool RBACManager::removePermissionFromRole(const std::string& roleId, const Permission& permission) {
    auto it = roles_.find(roleId);
    if (it == roles_.end()) {
        return false;
    }
    return it->second.permissions.erase(permission) > 0;
}

std::vector<Permission> RBACManager::getPermissionsForRole(const std::string& roleId) const {
    auto it = roles_.find(roleId);
    if (it == roles_.end()) {
        return {};
    }
    return {it->second.permissions.begin(), it->second.permissions.end()};
}

bool RBACManager::assignRoleToUser(const std::string& userId, const std::string& roleId) {
    if (!roles_.contains(roleId)) {
        return false;
    }
    userRoles_[userId].insert(roleId);
    return true;
}

bool RBACManager::removeRoleFromUser(const std::string& userId, const std::string& roleId) {
    auto it = userRoles_.find(userId);
    if (it == userRoles_.end()) {
        return false;
    }
    return it->second.erase(roleId) > 0;
}

std::vector<std::string> RBACManager::getUserRoles(const std::string& userId) const {
    auto it = userRoles_.find(userId);
    if (it == userRoles_.end()) {
        return {};
    }
    return {it->second.begin(), it->second.end()};
}

bool RBACManager::checkPermission(const std::string& userId, const std::string& module, PermissionType type) const {
    auto userIt = userRoles_.find(userId);
    if (userIt == userRoles_.end()) {
        return false;
    }

    for (const auto& roleId : userIt->second) {
        auto roleIt = roles_.find(roleId);
        if (roleIt == roles_.end()) {
            continue;
        }

        for (const auto& perm : roleIt->second.permissions) {
            // Check wildcard module or exact match
            if ((perm.module == "*" || perm.module == module) && perm.type == type) {
                return true;
            }
        }
    }
    return false;
}

bool RBACManager::hasRole(const std::string& userId, const std::string& roleId) const {
    auto it = userRoles_.find(userId);
    if (it == userRoles_.end()) {
        return false;
    }
    return it->second.contains(roleId);
}

std::vector<RoleDefinition> RBACManager::getAllRoles() const {
    std::vector<RoleDefinition> result;
    result.reserve(roles_.size());
    for (const auto& [id, role] : roles_) {
        result.push_back(role);
    }
    return result;
}

} // namespace ThreatOne::Identity
