#include <doctest/doctest.h>
#include <identity/LDAPConnector.h>

using namespace ThreatOne::Identity;

TEST_CASE("LDAP - Not connected initially") {
    LDAPConnector ldap;
    CHECK_FALSE(ldap.isConnected());
}

TEST_CASE("LDAP - Connect with valid config") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.port = 389;
    config.baseDN = "dc=corp,dc=local";
    config.bindDN = "cn=admin,dc=corp,dc=local";
    config.bindPassword = "secret";
    CHECK(ldap.connect(config));
    CHECK(ldap.isConnected());
}

TEST_CASE("LDAP - Connect with empty host fails") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.baseDN = "dc=corp,dc=local";
    CHECK_FALSE(ldap.connect(config));
    CHECK_FALSE(ldap.isConnected());
}

TEST_CASE("LDAP - Connect with empty baseDN fails") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    CHECK_FALSE(ldap.connect(config));
}

TEST_CASE("LDAP - Disconnect") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);
    CHECK(ldap.isConnected());
    ldap.disconnect();
    CHECK_FALSE(ldap.isConnected());
}

TEST_CASE("LDAP - Test connection") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);
    CHECK(ldap.testConnection());
}

TEST_CASE("LDAP - Search all users returns mock data") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);
    auto users = ldap.searchUsers();
    CHECK(users.size() == 3);
}

TEST_CASE("LDAP - Search with filter") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);
    auto users = ldap.searchUsers("admin");
    CHECK(users.size() == 1);
    CHECK(users[0].uid == "admin");
}

TEST_CASE("LDAP - Search with no match") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);
    auto users = ldap.searchUsers("nonexistent");
    CHECK(users.empty());
}

TEST_CASE("LDAP - Search when disconnected returns empty") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);
    ldap.disconnect();
    auto users = ldap.searchUsers();
    CHECK(users.empty());
}

TEST_CASE("LDAP - Sync users") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);
    auto users = ldap.syncUsers();
    CHECK(users.size() == 3);
}

TEST_CASE("LDAP - User has expected fields") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);
    auto users = ldap.searchUsers("Jane");
    REQUIRE(users.size() == 1);
    CHECK_FALSE(users[0].dn.empty());
    CHECK_FALSE(users[0].cn.empty());
    CHECK_FALSE(users[0].mail.empty());
    CHECK(users[0].memberOf.size() > 0);
}

TEST_CASE("LDAP - Add group mapping") {
    LDAPConnector ldap;
    ldap.addGroupMapping({"admins", "admin-role"});
    auto mappings = ldap.getGroupMappings();
    CHECK(mappings.size() == 1);
    CHECK(mappings[0].ldapGroup == "admins");
    CHECK(mappings[0].roleId == "admin-role");
}

TEST_CASE("LDAP - Replace existing mapping") {
    LDAPConnector ldap;
    ldap.addGroupMapping({"admins", "old-role"});
    ldap.addGroupMapping({"admins", "new-role"});
    auto mappings = ldap.getGroupMappings();
    CHECK(mappings.size() == 1);
    CHECK(mappings[0].roleId == "new-role");
}

TEST_CASE("LDAP - Map user to roles") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);

    ldap.addGroupMapping({"admins", "admin-role"});
    ldap.addGroupMapping({"analysts", "analyst-role"});
    ldap.addGroupMapping({"users", "user-role"});

    auto users = ldap.searchUsers("admin");
    REQUIRE(users.size() == 1);

    auto roles = ldap.mapUserToRoles(users[0]);
    CHECK(roles.size() >= 1);
    bool hasAdminRole = false;
    for (const auto& role : roles) {
        if (role == "admin-role") hasAdminRole = true;
    }
    CHECK(hasAdminRole);
}

TEST_CASE("LDAP - User with no matching groups has no roles") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.baseDN = "dc=corp,dc=local";
    ldap.connect(config);

    ldap.addGroupMapping({"special-group", "special-role"});

    auto users = ldap.searchUsers("Bob");
    REQUIRE(users.size() == 1);

    auto roles = ldap.mapUserToRoles(users[0]);
    bool hasSpecial = false;
    for (const auto& role : roles) {
        if (role == "special-role") hasSpecial = true;
    }
    CHECK_FALSE(hasSpecial);
}

TEST_CASE("LDAP - Configuration stored correctly") {
    LDAPConnector ldap;
    LDAPConfig config;
    config.host = "ldap.corp.local";
    config.port = 636;
    config.baseDN = "dc=corp,dc=local";
    config.bindDN = "cn=service,dc=corp,dc=local";
    config.bindPassword = "password123";
    config.useTLS = true;
    config.searchFilter = "(objectClass=user)";
    config.timeoutSeconds = 60;

    ldap.connect(config);
    auto retrieved = ldap.getConfig();
    CHECK(retrieved.host == "ldap.corp.local");
    CHECK(retrieved.port == 636);
    CHECK(retrieved.baseDN == "dc=corp,dc=local");
    CHECK(retrieved.useTLS);
    CHECK(retrieved.timeoutSeconds == 60);
}
