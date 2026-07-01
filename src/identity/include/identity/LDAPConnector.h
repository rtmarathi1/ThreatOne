#pragma once

#include <string>
#include <vector>
#include <unordered_map>

namespace ThreatOne::Identity {

struct LDAPConfig {
    std::string host;
    int port = 389;
    std::string baseDN;
    std::string bindDN;
    std::string bindPassword;
    std::string searchFilter = "(objectClass=person)";
    bool useTLS = false;
    int timeoutSeconds = 30;
    int maxResults = 1000;
};

struct LDAPUser {
    std::string dn;
    std::string cn;
    std::string mail;
    std::string uid;
    std::vector<std::string> memberOf;
    std::unordered_map<std::string, std::string> attributes;
};

struct LDAPGroupMapping {
    std::string ldapGroup;
    std::string roleId;
};

class ILDAPConnector {
public:
    virtual ~ILDAPConnector() = default;

    virtual bool connect(const LDAPConfig& config) = 0;
    virtual void disconnect() = 0;
    virtual bool isConnected() const = 0;

    virtual std::vector<LDAPUser> searchUsers(const std::string& filter = "") = 0;
    virtual std::vector<LDAPUser> syncUsers() = 0;
    virtual bool testConnection() = 0;

    virtual void addGroupMapping(const LDAPGroupMapping& mapping) = 0;
    virtual std::vector<LDAPGroupMapping> getGroupMappings() const = 0;
    virtual std::vector<std::string> mapUserToRoles(const LDAPUser& user) const = 0;
};

class LDAPConnector : public ILDAPConnector {
public:
    LDAPConnector() = default;
    ~LDAPConnector() override = default;

    bool connect(const LDAPConfig& config) override;
    void disconnect() override;
    bool isConnected() const override;

    std::vector<LDAPUser> searchUsers(const std::string& filter = "") override;
    std::vector<LDAPUser> syncUsers() override;
    bool testConnection() override;

    void addGroupMapping(const LDAPGroupMapping& mapping) override;
    std::vector<LDAPGroupMapping> getGroupMappings() const override;
    std::vector<std::string> mapUserToRoles(const LDAPUser& user) const override;

    // Configuration access
    const LDAPConfig& getConfig() const { return config_; }

private:
    LDAPConfig config_;
    bool connected_ = false;
    std::vector<LDAPGroupMapping> groupMappings_;
    std::vector<LDAPUser> cachedUsers_;
};

} // namespace ThreatOne::Identity
