#include <doctest/doctest.h>
#include <plugin/PluginSDK.h>

using namespace ThreatOne::Plugin;

TEST_CASE("PluginSDK - Create context") {
    PluginSDK sdk;

    std::set<PluginPermission> perms = {PluginPermission::NetworkAccess, PluginPermission::FileRead};
    auto ctx = sdk.createContext("test-plugin", perms);

    CHECK(ctx.pluginId == "test-plugin");
    CHECK(ctx.permissions.size() == 2);
    CHECK(ctx.apiVersion == "1.0.0");
    CHECK_FALSE(ctx.dataDirectory.empty());
}

TEST_CASE("PluginSDK - Get context") {
    PluginSDK sdk;

    sdk.createContext("plugin-a", {PluginPermission::FileRead});

    auto ctx = sdk.getContext("plugin-a");
    CHECK(ctx.pluginId == "plugin-a");
    CHECK(ctx.permissions.size() == 1);
}

TEST_CASE("PluginSDK - Get nonexistent context") {
    PluginSDK sdk;
    auto ctx = sdk.getContext("nonexistent");
    CHECK(ctx.pluginId.empty());
}

TEST_CASE("PluginSDK - Remove context") {
    PluginSDK sdk;
    sdk.createContext("plugin-a", {});
    CHECK(sdk.hasContext("plugin-a"));
    CHECK(sdk.removeContext("plugin-a"));
    CHECK_FALSE(sdk.hasContext("plugin-a"));
}

TEST_CASE("PluginSDK - Remove nonexistent context fails") {
    PluginSDK sdk;
    CHECK_FALSE(sdk.removeContext("nonexistent"));
}

TEST_CASE("PluginSDK - Register and get hooks") {
    PluginSDK sdk;

    PluginHook hook1 = {"onScan", "scan", 10};
    PluginHook hook2 = {"onScanComplete", "scan", 5};
    PluginHook hook3 = {"onAlert", "alert", 1};

    sdk.registerHookPoint("scan", hook1);
    sdk.registerHookPoint("scan", hook2);
    sdk.registerHookPoint("alert", hook3);

    auto scanHooks = sdk.getHooksForEvent("scan");
    CHECK(scanHooks.size() == 2);
    CHECK(scanHooks[0].priority >= scanHooks[1].priority);

    auto alertHooks = sdk.getHooksForEvent("alert");
    CHECK(alertHooks.size() == 1);
}

TEST_CASE("PluginSDK - Get registered event types") {
    PluginSDK sdk;

    sdk.registerHookPoint("scan", {"h1", "scan", 1});
    sdk.registerHookPoint("alert", {"h2", "alert", 1});

    auto types = sdk.getRegisteredEventTypes();
    CHECK(types.size() == 2);
}

TEST_CASE("PluginSDK - Register and query services") {
    PluginSDK sdk;

    SDKService svc;
    svc.name = "logging";
    svc.version = "1.0.0";
    svc.description = "Logging service";
    svc.available = true;
    sdk.registerService(svc);

    CHECK(sdk.isServiceAvailable("logging"));
    CHECK_FALSE(sdk.isServiceAvailable("nonexistent"));

    auto services = sdk.getAvailableServices();
    CHECK(services.size() == 1);
}

TEST_CASE("PluginSDK - Context count") {
    PluginSDK sdk;
    sdk.createContext("p1", {});
    sdk.createContext("p2", {});
    CHECK(sdk.getContextCount() == 2);
}
