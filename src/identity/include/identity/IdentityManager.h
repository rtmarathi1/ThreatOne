#pragma once

#include "identity/IIdentityManager.h"
#include "core/Logger.h"
#include <string>
#include <vector>

namespace ThreatOne::Identity {

class IdentityManager : public IIdentityManager {
public:
    IdentityManager();
    ~IdentityManager() override = default;

    AuthResult authenticate(const std::string& username, const std::string& password, AuthMethod method) override;
    bool authorize(const std::string& userId, const std::string& resource, const std::string& action) override;
    std::string createUser(const UserInfo& user) override;
    std::vector<UserInfo> getUsers() override;
    std::vector<RoleInfo> getRoles() override;
    bool assignRole(const std::string& userId, const std::string& roleId) override;
    std::string createPolicy(const PolicyInfo& policy) override;

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Identity
