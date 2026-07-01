#pragma once

#include <string>
#include <vector>

namespace ThreatOne::Identity {

enum class AuthMethod {
    Local,
    LDAP,
    ActiveDirectory,
    AzureAD,
    SSO,
    OAuth2
};

struct UserInfo {
    std::string id;
    std::string username;
    std::string email;
    std::string displayName;
    std::vector<std::string> roles;
    bool active = true;
};

struct RoleInfo {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> permissions;
};

struct AuthResult {
    bool success = false;
    std::string token;
    std::string userId;
    std::string error;
};

struct PolicyInfo {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> rules;
    bool enabled = true;
};

class IIdentityManager {
public:
    virtual ~IIdentityManager() = default;

    virtual AuthResult authenticate(const std::string& username, const std::string& password, AuthMethod method) = 0;
    virtual bool authorize(const std::string& userId, const std::string& resource, const std::string& action) = 0;
    virtual std::string createUser(const UserInfo& user) = 0;
    virtual std::vector<UserInfo> getUsers() = 0;
    virtual std::vector<RoleInfo> getRoles() = 0;
    virtual bool assignRole(const std::string& userId, const std::string& roleId) = 0;
    virtual std::string createPolicy(const PolicyInfo& policy) = 0;
};

} // namespace ThreatOne::Identity
