#include <doctest/doctest.h>
#include <plugin/PluginManager.h>
#include <vector>

using namespace ThreatOne::Plugin;

TEST_CASE("PluginManager - Load plugin") {
    PluginManager mgr;

    CHECK(mgr.loadPlugin("path/to/my_plugin.so"));

    auto plugins = mgr.getPlugins();
    REQUIRE(plugins.size() == 1);
    CHECK(plugins[0].id == "my_plugin");
    CHECK(plugins[0].loaded == true);
    CHECK(plugins[0].state == PluginState::Loaded);
}

TEST_CASE("PluginManager - Load plugin empty path fails") {
    PluginManager mgr;
    CHECK_FALSE(mgr.loadPlugin(""));
}

TEST_CASE("PluginManager - Load plugin duplicate fails") {
    PluginManager mgr;
    CHECK(mgr.loadPlugin("my_plugin"));
    CHECK_FALSE(mgr.loadPlugin("my_plugin"));
}

TEST_CASE("PluginManager - Unload plugin") {
    PluginManager mgr;
    mgr.loadPlugin("test_plugin");

    CHECK(mgr.unloadPlugin("test_plugin"));

    auto state = mgr.getPluginState("test_plugin");
    REQUIRE(state.has_value());
    CHECK(state.value() == PluginState::Unloaded);
}

TEST_CASE("PluginManager - Unload nonexistent plugin fails") {
    PluginManager mgr;
    CHECK_FALSE(mgr.unloadPlugin("nonexistent"));
}

TEST_CASE("PluginManager - Unload already unloaded plugin fails") {
    PluginManager mgr;
    mgr.loadPlugin("test_plugin");
    mgr.unloadPlugin("test_plugin");
    CHECK_FALSE(mgr.unloadPlugin("test_plugin"));
}

TEST_CASE("PluginManager - Reload plugin") {
    PluginManager mgr;
    mgr.loadPlugin("test_plugin");

    CHECK(mgr.reloadPlugin("test_plugin"));

    auto state = mgr.getPluginState("test_plugin");
    REQUIRE(state.has_value());
    CHECK(state.value() == PluginState::Loaded);
}

TEST_CASE("PluginManager - Reload nonexistent plugin fails") {
    PluginManager mgr;
    CHECK_FALSE(mgr.reloadPlugin("nonexistent"));
}

TEST_CASE("PluginManager - Enable plugin") {
    PluginManager mgr;
    mgr.loadPlugin("test_plugin");

    CHECK(mgr.enablePlugin("test_plugin"));

    auto state = mgr.getPluginState("test_plugin");
    REQUIRE(state.has_value());
    CHECK(state.value() == PluginState::Enabled);

    auto plugins = mgr.getPlugins();
    REQUIRE(plugins.size() == 1);
    CHECK(plugins[0].enabled == true);
}

TEST_CASE("PluginManager - Disable plugin") {
    PluginManager mgr;
    mgr.loadPlugin("test_plugin");
    mgr.enablePlugin("test_plugin");

    CHECK(mgr.disablePlugin("test_plugin"));

    auto state = mgr.getPluginState("test_plugin");
    REQUIRE(state.has_value());
    CHECK(state.value() == PluginState::Disabled);
}

TEST_CASE("PluginManager - Enable nonexistent plugin fails") {
    PluginManager mgr;
    CHECK_FALSE(mgr.enablePlugin("nonexistent"));
}

TEST_CASE("PluginManager - State transitions") {
    PluginManager mgr;
    mgr.loadPlugin("test_plugin");

    // Loaded -> Enabled
    CHECK(mgr.enablePlugin("test_plugin"));
    CHECK(mgr.getPluginState("test_plugin").value() == PluginState::Enabled);

    // Enabled -> Disabled
    CHECK(mgr.disablePlugin("test_plugin"));
    CHECK(mgr.getPluginState("test_plugin").value() == PluginState::Disabled);

    // Disabled -> Enabled (should work, since Disabled is a valid source state)
    CHECK(mgr.enablePlugin("test_plugin"));
    CHECK(mgr.getPluginState("test_plugin").value() == PluginState::Enabled);
}

TEST_CASE("PluginManager - Get plugin state nonexistent") {
    PluginManager mgr;
    auto state = mgr.getPluginState("nonexistent");
    CHECK_FALSE(state.has_value());
}

TEST_CASE("PluginManager - Set and check permissions") {
    PluginManager mgr;
    mgr.loadPlugin("test_plugin");

    std::vector<PluginPermission> perms = {
        PluginPermission::NetworkAccess,
        PluginPermission::FileRead
    };
    CHECK(mgr.setPluginPermissions("test_plugin", perms));

    CHECK(mgr.checkPermission("test_plugin", PluginPermission::NetworkAccess));
    CHECK(mgr.checkPermission("test_plugin", PluginPermission::FileRead));
    CHECK_FALSE(mgr.checkPermission("test_plugin", PluginPermission::FileWrite));
    CHECK_FALSE(mgr.checkPermission("test_plugin", PluginPermission::APIAccess));
}

TEST_CASE("PluginManager - Get permissions") {
    PluginManager mgr;
    mgr.loadPlugin("test_plugin");

    std::vector<PluginPermission> perms = {
        PluginPermission::NetworkAccess,
        PluginPermission::FileRead,
        PluginPermission::SystemInfo
    };
    mgr.setPluginPermissions("test_plugin", perms);

    auto retrieved = mgr.getPluginPermissions("test_plugin");
    CHECK(retrieved.size() == 3);
}

TEST_CASE("PluginManager - Check permission nonexistent plugin") {
    PluginManager mgr;
    CHECK_FALSE(mgr.checkPermission("nonexistent", PluginPermission::NetworkAccess));
}

TEST_CASE("PluginManager - Set permissions nonexistent plugin fails") {
    PluginManager mgr;
    CHECK_FALSE(mgr.setPluginPermissions("nonexistent", {PluginPermission::FileRead}));
}

TEST_CASE("PluginManager - Dependency resolution simple chain") {
    PluginManager mgr;

    // Create manifests: C depends on B, B depends on A
    PluginManifest manifestA;
    manifestA.id = "plugin_a";
    manifestA.name = "Plugin A";
    manifestA.version = "1.0.0";
    mgr.registerManifest(manifestA);

    PluginManifest manifestB;
    manifestB.id = "plugin_b";
    manifestB.name = "Plugin B";
    manifestB.version = "1.0.0";
    manifestB.dependencies.push_back({"plugin_a", "1.0.0", true});
    mgr.registerManifest(manifestB);

    PluginManifest manifestC;
    manifestC.id = "plugin_c";
    manifestC.name = "Plugin C";
    manifestC.version = "1.0.0";
    manifestC.dependencies.push_back({"plugin_b", "1.0.0", true});
    mgr.registerManifest(manifestC);

    // Load all plugins
    mgr.loadPlugin("plugin_a");
    mgr.loadPlugin("plugin_b");
    mgr.loadPlugin("plugin_c");

    auto deps = mgr.resolveDependencies("plugin_c");
    REQUIRE(deps.size() == 2);
    // A should come before B (topological order)
    CHECK(deps[0] == "plugin_a");
    CHECK(deps[1] == "plugin_b");
}

TEST_CASE("PluginManager - Dependency resolution detects missing") {
    PluginManager mgr;

    PluginManifest manifest;
    manifest.id = "plugin_with_missing_dep";
    manifest.name = "Plugin With Missing Dep";
    manifest.version = "1.0.0";
    manifest.dependencies.push_back({"nonexistent_plugin", "1.0.0", true});
    mgr.registerManifest(manifest);

    auto deps = mgr.resolveDependencies("plugin_with_missing_dep");
    REQUIRE(deps.size() == 1);
    CHECK(deps[0] == "MISSING:nonexistent_plugin");
}

TEST_CASE("PluginManager - Dependency resolution no manifest") {
    PluginManager mgr;
    mgr.loadPlugin("simple_plugin");

    auto deps = mgr.resolveDependencies("simple_plugin");
    CHECK(deps.empty());
}

TEST_CASE("PluginManager - Unload plugin with dependents fails") {
    PluginManager mgr;

    PluginManifest manifestA;
    manifestA.id = "base_plugin";
    manifestA.name = "Base Plugin";
    manifestA.version = "1.0.0";
    mgr.registerManifest(manifestA);

    PluginManifest manifestB;
    manifestB.id = "dependent_plugin";
    manifestB.name = "Dependent Plugin";
    manifestB.version = "1.0.0";
    manifestB.dependencies.push_back({"base_plugin", "1.0.0", true});
    mgr.registerManifest(manifestB);

    mgr.loadPlugin("base_plugin");
    mgr.loadPlugin("dependent_plugin");

    // Should fail because dependent_plugin requires base_plugin
    CHECK_FALSE(mgr.unloadPlugin("base_plugin"));
}

TEST_CASE("PluginManager - Plugin hooks") {
    PluginManager mgr;

    PluginManifest manifest;
    manifest.id = "hook_plugin";
    manifest.name = "Hook Plugin";
    manifest.version = "1.0.0";
    manifest.hooks.push_back({"onScan", "scan", 10});
    manifest.hooks.push_back({"onAlert", "alert", 5});
    manifest.hooks.push_back({"onScanComplete", "scan", 1});
    mgr.registerManifest(manifest);

    mgr.loadPlugin("hook_plugin");

    auto scanHooks = mgr.getPluginHooks("scan");
    REQUIRE(scanHooks.size() == 2);
    CHECK(scanHooks[0].priority >= scanHooks[1].priority);  // sorted by priority desc

    auto alertHooks = mgr.getPluginHooks("alert");
    CHECK(alertHooks.size() == 1);
    CHECK(alertHooks[0].name == "onAlert");

    auto noHooks = mgr.getPluginHooks("nonexistent_event");
    CHECK(noHooks.empty());
}

TEST_CASE("PluginManager - Marketplace search") {
    PluginManager mgr;

    MarketplaceEntry entry1;
    entry1.id = "security_scanner";
    entry1.name = "Security Scanner Pro";
    entry1.version = "2.0.0";
    entry1.author = "SecCo";
    entry1.description = "Advanced security scanning tool";
    entry1.downloads = 1000;
    entry1.rating = 4.5;
    mgr.addMarketplaceEntry(entry1);

    MarketplaceEntry entry2;
    entry2.id = "network_monitor";
    entry2.name = "Network Monitor";
    entry2.version = "1.5.0";
    entry2.author = "NetCo";
    entry2.description = "Real-time network monitoring";
    entry2.downloads = 500;
    entry2.rating = 4.0;
    mgr.addMarketplaceEntry(entry2);

    // Search by name
    auto results = mgr.searchMarketplace("security");
    REQUIRE(results.size() == 1);
    CHECK(results[0].id == "security_scanner");

    // Search by description
    results = mgr.searchMarketplace("network");
    REQUIRE(results.size() == 1);
    CHECK(results[0].id == "network_monitor");

    // Empty search returns all
    results = mgr.searchMarketplace("");
    CHECK(results.size() == 2);
}

TEST_CASE("PluginManager - Get marketplace entry") {
    PluginManager mgr;

    MarketplaceEntry entry;
    entry.id = "test_entry";
    entry.name = "Test Entry";
    entry.version = "1.0.0";
    mgr.addMarketplaceEntry(entry);

    auto retrieved = mgr.getMarketplaceEntry("test_entry");
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Test Entry");

    auto missing = mgr.getMarketplaceEntry("nonexistent");
    CHECK_FALSE(missing.has_value());
}

TEST_CASE("PluginManager - Compatibility check") {
    PluginManager mgr;

    MarketplaceEntry entry;
    entry.id = "compat_plugin";
    entry.name = "Compatible Plugin";
    entry.version = "1.0.0";
    entry.compatibleVersions = {"1.0.0", "1.1.0", "2.0.0"};
    mgr.addMarketplaceEntry(entry);

    CHECK(mgr.checkCompatibility("compat_plugin", "1.0.0"));
    CHECK(mgr.checkCompatibility("compat_plugin", "2.0.0"));
    CHECK_FALSE(mgr.checkCompatibility("compat_plugin", "3.0.0"));
    CHECK_FALSE(mgr.checkCompatibility("nonexistent", "1.0.0"));
}

TEST_CASE("PluginManager - Install from marketplace") {
    PluginManager mgr;

    MarketplaceEntry entry;
    entry.id = "installable_plugin";
    entry.name = "Installable Plugin";
    entry.version = "1.0.0";
    mgr.addMarketplaceEntry(entry);

    CHECK(mgr.installFromMarketplace("installable_plugin"));

    auto plugins = mgr.getPlugins();
    REQUIRE(plugins.size() == 1);
    CHECK(plugins[0].id == "installable_plugin");
    CHECK(plugins[0].state == PluginState::Loaded);
}

TEST_CASE("PluginManager - Install from marketplace nonexistent fails") {
    PluginManager mgr;
    CHECK_FALSE(mgr.installFromMarketplace("nonexistent"));
}

TEST_CASE("PluginManager - Get marketplace") {
    PluginManager mgr;

    MarketplaceEntry entry1;
    entry1.id = "p1";
    entry1.name = "Plugin 1";
    mgr.addMarketplaceEntry(entry1);

    MarketplaceEntry entry2;
    entry2.id = "p2";
    entry2.name = "Plugin 2";
    mgr.addMarketplaceEntry(entry2);

    auto marketplace = mgr.getMarketplace();
    CHECK(marketplace.size() == 2);
}

TEST_CASE("PluginManager - Load plugin with manifest") {
    PluginManager mgr;

    PluginManifest manifest;
    manifest.id = "manifest_plugin";
    manifest.name = "Manifest Plugin";
    manifest.version = "2.5.0";
    manifest.author = "TestAuthor";
    manifest.description = "A plugin with a manifest";
    manifest.entryPoint = "main.so";
    mgr.registerManifest(manifest);

    CHECK(mgr.loadPlugin("manifest_plugin"));

    auto plugins = mgr.getPlugins();
    REQUIRE(plugins.size() == 1);
    CHECK(plugins[0].name == "Manifest Plugin");
    CHECK(plugins[0].version == "2.5.0");
    CHECK(plugins[0].author == "TestAuthor");
}
