#include <doctest/doctest.h>
#include <plugin/PluginPermissions.h>

using namespace ThreatOne::Plugin;

TEST_CASE("PluginPermissions - Register and set permissions") {
    PluginPermissions perms;

    CHECK(perms.registerPlugin("plugin-a"));
    CHECK(perms.setPermissions("plugin-a", {PluginPermission::NetworkAccess, PluginPermission::FileRead}));

    auto retrieved = perms.getPermissions("plugin-a");
    CHECK(retrieved.size() == 2);
}

TEST_CASE("PluginPermissions - Set permissions for unregistered fails") {
    PluginPermissions perms;
    CHECK_FALSE(perms.setPermissions("unregistered", {PluginPermission::FileRead}));
}

TEST_CASE("PluginPermissions - Grant and revoke") {
    PluginPermissions perms;
    perms.registerPlugin("plugin-a");

    CHECK(perms.grantPermission("plugin-a", PluginPermission::NetworkAccess));
    CHECK(perms.hasPermission("plugin-a", PluginPermission::NetworkAccess));

    CHECK(perms.revokePermission("plugin-a", PluginPermission::NetworkAccess));
    CHECK_FALSE(perms.hasPermission("plugin-a", PluginPermission::NetworkAccess));
}

TEST_CASE("PluginPermissions - Revoke all") {
    PluginPermissions perms;
    perms.registerPlugin("plugin-a");
    perms.grantPermission("plugin-a", PluginPermission::NetworkAccess);
    perms.grantPermission("plugin-a", PluginPermission::FileRead);

    CHECK(perms.revokeAllPermissions("plugin-a"));
    CHECK_FALSE(perms.hasAnyPermissions("plugin-a"));
}

TEST_CASE("PluginPermissions - Check access") {
    PluginPermissions perms;
    perms.registerPlugin("plugin-a");
    perms.grantPermission("plugin-a", PluginPermission::FileRead);

    CHECK(perms.checkAccess("plugin-a", PluginPermission::FileRead));
    CHECK_FALSE(perms.checkAccess("plugin-a", PluginPermission::FileWrite));
}

TEST_CASE("PluginPermissions - Missing permissions") {
    PluginPermissions perms;
    perms.registerPlugin("plugin-a");
    perms.grantPermission("plugin-a", PluginPermission::FileRead);

    std::vector<PluginPermission> required = {
        PluginPermission::FileRead,
        PluginPermission::FileWrite,
        PluginPermission::NetworkAccess
    };

    auto missing = perms.getMissingPermissions("plugin-a", required);
    CHECK(missing.size() == 2);
}

TEST_CASE("PluginPermissions - Audit log") {
    PluginPermissions perms;
    perms.registerPlugin("plugin-a");
    perms.grantPermission("plugin-a", PluginPermission::FileRead);
    perms.revokePermission("plugin-a", PluginPermission::FileRead);

    auto log = perms.getAuditLog();
    CHECK(log.size() == 2);
    CHECK(log[0].granted);
    CHECK_FALSE(log[1].granted);
}

TEST_CASE("PluginPermissions - Register duplicate fails") {
    PluginPermissions perms;
    CHECK(perms.registerPlugin("plugin-a"));
    CHECK_FALSE(perms.registerPlugin("plugin-a"));
}

TEST_CASE("PluginPermissions - Unregister plugin") {
    PluginPermissions perms;
    perms.registerPlugin("plugin-a");
    CHECK(perms.isRegistered("plugin-a"));
    CHECK(perms.unregisterPlugin("plugin-a"));
    CHECK_FALSE(perms.isRegistered("plugin-a"));
}

TEST_CASE("PluginPermissions - Registered plugin count") {
    PluginPermissions perms;
    perms.registerPlugin("p1");
    perms.registerPlugin("p2");
    CHECK(perms.getRegisteredPluginCount() == 2);
}
