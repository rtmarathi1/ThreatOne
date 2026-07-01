#include <doctest/doctest.h>
#include <identity/RBACManager.h>

using namespace ThreatOne::Identity;

TEST_CASE("RBAC - Default roles exist") {
    RBACManager rbac;
    CHECK(rbac.roleExists("admin"));
    CHECK(rbac.roleExists("analyst"));
    CHECK(rbac.roleExists("viewer"));
    CHECK_FALSE(rbac.roleExists("nonexistent"));
}

TEST_CASE("RBAC - Add custom role") {
    RBACManager rbac;
    bool added = rbac.addRole("custom_role", "Custom Role", Role::Custom);
    CHECK(added);
    CHECK(rbac.roleExists("custom_role"));
}

TEST_CASE("RBAC - Cannot add duplicate role") {
    RBACManager rbac;
    bool added = rbac.addRole("admin", "Duplicate Admin", Role::Admin);
    CHECK_FALSE(added);
}

TEST_CASE("RBAC - Remove role") {
    RBACManager rbac;
    rbac.addRole("temp_role", "Temporary", Role::Custom);
    CHECK(rbac.roleExists("temp_role"));
    bool removed = rbac.removeRole("temp_role");
    CHECK(removed);
    CHECK_FALSE(rbac.roleExists("temp_role"));
}

TEST_CASE("RBAC - Remove nonexistent role returns false") {
    RBACManager rbac;
    CHECK_FALSE(rbac.removeRole("ghost_role"));
}

TEST_CASE("RBAC - Get all roles includes defaults") {
    RBACManager rbac;
    auto roles = rbac.getAllRoles();
    CHECK(roles.size() >= 3);
}

TEST_CASE("RBAC - Add permission to role") {
    RBACManager rbac;
    rbac.addRole("custom", "Custom", Role::Custom);
    bool added = rbac.addPermissionToRole("custom", {"scanner", PermissionType::Read});
    CHECK(added);

    auto perms = rbac.getPermissionsForRole("custom");
    CHECK(perms.size() == 1);
    CHECK(perms[0].module == "scanner");
    CHECK(perms[0].type == PermissionType::Read);
}

TEST_CASE("RBAC - Cannot add permission to nonexistent role") {
    RBACManager rbac;
    bool added = rbac.addPermissionToRole("ghost", {"scanner", PermissionType::Read});
    CHECK_FALSE(added);
}

TEST_CASE("RBAC - Remove permission from role") {
    RBACManager rbac;
    rbac.addRole("custom", "Custom", Role::Custom);
    Permission perm{"scanner", PermissionType::Write};
    rbac.addPermissionToRole("custom", perm);
    bool removed = rbac.removePermissionFromRole("custom", perm);
    CHECK(removed);
    auto perms = rbac.getPermissionsForRole("custom");
    CHECK(perms.empty());
}

TEST_CASE("RBAC - Admin has wildcard permissions") {
    RBACManager rbac;
    auto perms = rbac.getPermissionsForRole("admin");
    CHECK(perms.size() == 3); // read, write, execute on *
}

TEST_CASE("RBAC - Assign role to user") {
    RBACManager rbac;
    bool assigned = rbac.assignRoleToUser("user1", "admin");
    CHECK(assigned);
    CHECK(rbac.hasRole("user1", "admin"));
}

TEST_CASE("RBAC - Cannot assign nonexistent role") {
    RBACManager rbac;
    bool assigned = rbac.assignRoleToUser("user1", "ghost");
    CHECK_FALSE(assigned);
}

TEST_CASE("RBAC - Get user roles") {
    RBACManager rbac;
    rbac.assignRoleToUser("user1", "admin");
    rbac.assignRoleToUser("user1", "analyst");
    auto roles = rbac.getUserRoles("user1");
    CHECK(roles.size() == 2);
}

TEST_CASE("RBAC - Remove role from user") {
    RBACManager rbac;
    rbac.assignRoleToUser("user1", "viewer");
    bool removed = rbac.removeRoleFromUser("user1", "viewer");
    CHECK(removed);
    CHECK_FALSE(rbac.hasRole("user1", "viewer"));
}

TEST_CASE("RBAC - Removing deleted role from users") {
    RBACManager rbac;
    rbac.assignRoleToUser("user1", "viewer");
    rbac.removeRole("viewer");
    CHECK_FALSE(rbac.hasRole("user1", "viewer"));
}

TEST_CASE("RBAC - Admin can do everything") {
    RBACManager rbac;
    rbac.assignRoleToUser("admin_user", "admin");
    CHECK(rbac.checkPermission("admin_user", "scanner", PermissionType::Read));
    CHECK(rbac.checkPermission("admin_user", "scanner", PermissionType::Write));
    CHECK(rbac.checkPermission("admin_user", "scanner", PermissionType::Execute));
    CHECK(rbac.checkPermission("admin_user", "edr", PermissionType::Write));
}

TEST_CASE("RBAC - Analyst can read and execute but not write") {
    RBACManager rbac;
    rbac.assignRoleToUser("analyst_user", "analyst");
    CHECK(rbac.checkPermission("analyst_user", "scanner", PermissionType::Read));
    CHECK(rbac.checkPermission("analyst_user", "scanner", PermissionType::Execute));
    CHECK_FALSE(rbac.checkPermission("analyst_user", "scanner", PermissionType::Write));
}

TEST_CASE("RBAC - Viewer can only read") {
    RBACManager rbac;
    rbac.assignRoleToUser("viewer_user", "viewer");
    CHECK(rbac.checkPermission("viewer_user", "scanner", PermissionType::Read));
    CHECK_FALSE(rbac.checkPermission("viewer_user", "scanner", PermissionType::Write));
    CHECK_FALSE(rbac.checkPermission("viewer_user", "scanner", PermissionType::Execute));
}

TEST_CASE("RBAC - User without role has no permissions") {
    RBACManager rbac;
    CHECK_FALSE(rbac.checkPermission("nobody", "scanner", PermissionType::Read));
}

TEST_CASE("RBAC - Custom role with specific module permission") {
    RBACManager rbac;
    rbac.addRole("scanner_reader", "Scanner Reader", Role::Custom);
    rbac.addPermissionToRole("scanner_reader", {"scanner", PermissionType::Read});
    rbac.assignRoleToUser("user1", "scanner_reader");

    CHECK(rbac.checkPermission("user1", "scanner", PermissionType::Read));
    CHECK_FALSE(rbac.checkPermission("user1", "scanner", PermissionType::Write));
    CHECK_FALSE(rbac.checkPermission("user1", "edr", PermissionType::Read));
}

TEST_CASE("RBAC - Multiple roles combine permissions") {
    RBACManager rbac;
    rbac.addRole("r1", "Role 1", Role::Custom);
    rbac.addRole("r2", "Role 2", Role::Custom);
    rbac.addPermissionToRole("r1", {"scanner", PermissionType::Read});
    rbac.addPermissionToRole("r2", {"edr", PermissionType::Write});

    rbac.assignRoleToUser("multi_user", "r1");
    rbac.assignRoleToUser("multi_user", "r2");

    CHECK(rbac.checkPermission("multi_user", "scanner", PermissionType::Read));
    CHECK(rbac.checkPermission("multi_user", "edr", PermissionType::Write));
    CHECK_FALSE(rbac.checkPermission("multi_user", "scanner", PermissionType::Write));
    CHECK_FALSE(rbac.checkPermission("multi_user", "edr", PermissionType::Read));
}
