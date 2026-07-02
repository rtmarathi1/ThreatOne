#include <doctest/doctest.h>
#include <plugin/PluginVersionManager.h>

using namespace ThreatOne::Plugin;

TEST_CASE("PluginVersionManager - Register version") {
    PluginVersionManager mgr;

    std::string v = mgr.registerVersion("plugin-a", "1.0.0", "Initial release");
    CHECK(v == "1.0.0");
    CHECK(mgr.getCurrentVersion("plugin-a") == "1.0.0");
}

TEST_CASE("PluginVersionManager - Version history") {
    PluginVersionManager mgr;

    mgr.registerVersion("plugin-a", "1.0.0");
    mgr.registerVersion("plugin-a", "1.1.0");
    mgr.registerVersion("plugin-a", "2.0.0");

    auto history = mgr.getVersionHistory("plugin-a");
    CHECK(history.size() == 3);
    CHECK(mgr.getCurrentVersion("plugin-a") == "2.0.0");
}

TEST_CASE("PluginVersionManager - Migrate to version") {
    PluginVersionManager mgr;
    mgr.registerVersion("plugin-a", "1.0.0");

    auto result = mgr.migrateToVersion("plugin-a", "2.0.0");
    CHECK(result.success);
    CHECK(result.fromVersion == "1.0.0");
    CHECK(result.toVersion == "2.0.0");
    CHECK(mgr.getCurrentVersion("plugin-a") == "2.0.0");
}

TEST_CASE("PluginVersionManager - Migrate to same version fails") {
    PluginVersionManager mgr;
    mgr.registerVersion("plugin-a", "1.0.0");

    auto result = mgr.migrateToVersion("plugin-a", "1.0.0");
    CHECK_FALSE(result.success);
}

TEST_CASE("PluginVersionManager - Can migrate") {
    PluginVersionManager mgr;
    mgr.registerVersion("plugin-a", "1.0.0");

    CHECK(mgr.canMigrate("plugin-a", "2.0.0"));
    CHECK_FALSE(mgr.canMigrate("plugin-a", "1.0.0"));
    CHECK_FALSE(mgr.canMigrate("nonexistent", "1.0.0"));
}

TEST_CASE("PluginVersionManager - Rollback") {
    PluginVersionManager mgr;
    mgr.registerVersion("plugin-a", "1.0.0");
    mgr.registerVersion("plugin-a", "2.0.0");

    CHECK(mgr.canRollback("plugin-a"));

    auto result = mgr.rollback("plugin-a");
    CHECK(result.success);
    CHECK(result.fromVersion == "2.0.0");
    CHECK(result.toVersion == "1.0.0");
    CHECK(mgr.getCurrentVersion("plugin-a") == "1.0.0");
}

TEST_CASE("PluginVersionManager - Cannot rollback single version") {
    PluginVersionManager mgr;
    mgr.registerVersion("plugin-a", "1.0.0");

    CHECK_FALSE(mgr.canRollback("plugin-a"));
    auto result = mgr.rollback("plugin-a");
    CHECK_FALSE(result.success);
}

TEST_CASE("PluginVersionManager - Compare versions") {
    PluginVersionManager mgr;

    CHECK(mgr.compareVersions("1.0.0", "1.0.0") == 0);
    CHECK(mgr.compareVersions("1.0.0", "2.0.0") == -1);
    CHECK(mgr.compareVersions("2.0.0", "1.0.0") == 1);
    CHECK(mgr.compareVersions("1.2.0", "1.1.0") == 1);
    CHECK(mgr.compareVersions("1.0.1", "1.0.0") == 1);
}

TEST_CASE("PluginVersionManager - Is newer version") {
    PluginVersionManager mgr;

    CHECK(mgr.isNewerVersion("1.0.0", "2.0.0"));
    CHECK_FALSE(mgr.isNewerVersion("2.0.0", "1.0.0"));
    CHECK_FALSE(mgr.isNewerVersion("1.0.0", "1.0.0"));
}

TEST_CASE("PluginVersionManager - Remove version history") {
    PluginVersionManager mgr;
    mgr.registerVersion("plugin-a", "1.0.0");
    CHECK(mgr.getTrackedPluginCount() == 1);

    CHECK(mgr.removeVersionHistory("plugin-a"));
    CHECK(mgr.getTrackedPluginCount() == 0);
    CHECK(mgr.getCurrentVersion("plugin-a").empty());
}

TEST_CASE("PluginVersionManager - Previous version") {
    PluginVersionManager mgr;
    mgr.registerVersion("plugin-a", "1.0.0");
    mgr.registerVersion("plugin-a", "2.0.0");

    CHECK(mgr.getPreviousVersion("plugin-a") == "1.0.0");
}
