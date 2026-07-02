#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstddef>

namespace ThreatOne::Identity {

enum class Role {
    Admin,
    Analyst,
    Viewer,
    Custom
};

enum class PermissionType {
    Read,
    Write,
    Execute
};

struct Permission {
    std::string module;
    PermissionType type;

    bool operator==(const Permission& other) const {
        return module == other.module && type == other.type;
    }
};

struct PermissionHash {
    std::size_t operator()(const Permission& p) const {
        auto h1 = std::hash<std::string>{}(p.module);
        auto h2 = std::hash<int>{}(static_cast<int>(p.type));
        return h1 ^ (h2 << 1);
    }
};

struct RoleDefinition {
    std::string id;
    std::string name;
    Role type;
    std::unordered_set<Permission, PermissionHash> permissions;
};

class RBACManager {
public:
    RBACManager();
    ~RBACManager() = default;

    // Role management
    bool addRole(const std::string& roleId, const std::string& name, Role type);
    bool removeRole(const std::string& roleId);
    bool roleExists(const std::string& roleId) const;

    // Permission management
    bool addPermissionToRole(const std::string& roleId, const Permission& permission);
    bool removePermissionFromRole(const std::string& roleId, const Permission& permission);
    std::vector<Permission> getPermissionsForRole(const std::string& roleId) const;

    // User-role assignment
    bool assignRoleToUser(const std::string& userId, const std::string& roleId);
    bool removeRoleFromUser(const std::string& userId, const std::string& roleId);
    std::vector<std::string> getUserRoles(const std::string& userId) const;

    // Permission checking
    bool checkPermission(const std::string& userId, const std::string& module, PermissionType type) const;
    bool hasRole(const std::string& userId, const std::string& roleId) const;

    // Query
    std::vector<RoleDefinition> getAllRoles() const;

private:
    std::unordered_map<std::string, RoleDefinition> roles_;
    std::unordered_map<std::string, std::unordered_set<std::string>> userRoles_;
};

} // namespace ThreatOne::Identity
