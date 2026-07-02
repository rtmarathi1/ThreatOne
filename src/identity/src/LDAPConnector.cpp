#include "identity/LDAPConnector.h"

#include <algorithm>
#include <string>
#include <vector>

namespace ThreatOne::Identity {

bool LDAPConnector::connect(const LDAPConfig& config) {
    connected_ = false;
    cachedUsers_.clear();

    if (config.host.empty() || config.baseDN.empty()) {
        return false;
    }
    config_ = config;
    connected_ = true;

    // Simulate some default users that would come from an LDAP directory
    cachedUsers_ = {
        {"cn=admin,ou=users," + config.baseDN, "Admin User", "admin@corp.local", "admin",
         {"cn=admins,ou=groups," + config.baseDN, "cn=users,ou=groups," + config.baseDN}, {}},
        {"cn=analyst1,ou=users," + config.baseDN, "Jane Analyst", "jane@corp.local", "janalyst",
         {"cn=analysts,ou=groups," + config.baseDN, "cn=users,ou=groups," + config.baseDN}, {}},
        {"cn=viewer1,ou=users," + config.baseDN, "Bob Viewer", "bob@corp.local", "bviewer",
         {"cn=viewers,ou=groups," + config.baseDN}, {}}
    };

    return true;
}

void LDAPConnector::disconnect() {
    connected_ = false;
    cachedUsers_.clear();
}

bool LDAPConnector::isConnected() const {
    return connected_;
}

std::vector<LDAPUser> LDAPConnector::searchUsers(const std::string& filter) {
    if (!connected_) {
        return {};
    }

    if (filter.empty()) {
        return cachedUsers_;
    }

    // Simple filter matching on cn or mail
    std::vector<LDAPUser> results;
    for (const auto& user : cachedUsers_) {
        if (user.cn.find(filter) != std::string::npos ||
            user.mail.find(filter) != std::string::npos ||
            user.uid.find(filter) != std::string::npos) {
            results.push_back(user);
        }
    }
    return results;
}

std::vector<LDAPUser> LDAPConnector::syncUsers() {
    if (!connected_) {
        return {};
    }
    // In production, this would query the LDAP server for all users
    // and update the local cache
    return cachedUsers_;
}

bool LDAPConnector::testConnection() {
    return connected_;
}

void LDAPConnector::addGroupMapping(const LDAPGroupMapping& mapping) {
    // Replace existing mapping for the same LDAP group
    for (auto& existing : groupMappings_) {
        if (existing.ldapGroup == mapping.ldapGroup) {
            existing.roleId = mapping.roleId;
            return;
        }
    }
    groupMappings_.push_back(mapping);
}

std::vector<LDAPGroupMapping> LDAPConnector::getGroupMappings() const {
    return groupMappings_;
}

std::vector<std::string> LDAPConnector::mapUserToRoles(const LDAPUser& user) const {
    std::vector<std::string> roles;
    for (const auto& group : user.memberOf) {
        for (const auto& mapping : groupMappings_) {
            if (group.find(mapping.ldapGroup) != std::string::npos) {
                // Avoid duplicates
                if (std::find(roles.begin(), roles.end(), mapping.roleId) == roles.end()) {
                    roles.push_back(mapping.roleId);
                }
            }
        }
    }
    return roles;
}

} // namespace ThreatOne::Identity
