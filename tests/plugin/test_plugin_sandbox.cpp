#include <doctest/doctest.h>
#include <plugin/PluginSandbox.h>

using namespace ThreatOne::Plugin;

TEST_CASE("PluginSandbox - Create and destroy sandbox") {
    PluginSandbox sandbox;

    ResourceLimits limits;
    limits.maxMemoryBytes = 50000000;

    CHECK(sandbox.createSandbox("plugin-a", limits));
    CHECK(sandbox.hasSandbox("plugin-a"));

    CHECK(sandbox.destroySandbox("plugin-a"));
    CHECK_FALSE(sandbox.hasSandbox("plugin-a"));
}

TEST_CASE("PluginSandbox - Create duplicate fails") {
    PluginSandbox sandbox;
    ResourceLimits limits;

    CHECK(sandbox.createSandbox("plugin-a", limits));
    CHECK_FALSE(sandbox.createSandbox("plugin-a", limits));
}

TEST_CASE("PluginSandbox - Destroy nonexistent fails") {
    PluginSandbox sandbox;
    CHECK_FALSE(sandbox.destroySandbox("nonexistent"));
}

TEST_CASE("PluginSandbox - Resource limits") {
    PluginSandbox sandbox;
    ResourceLimits limits;
    limits.maxMemoryBytes = 100000;
    limits.maxCpuTimeMs = 5000;

    sandbox.createSandbox("plugin-a", limits);

    auto retrieved = sandbox.getResourceLimits("plugin-a");
    CHECK(retrieved.maxMemoryBytes == 100000);
    CHECK(retrieved.maxCpuTimeMs == 5000);
}

TEST_CASE("PluginSandbox - Memory usage tracking") {
    PluginSandbox sandbox;
    ResourceLimits limits;
    limits.maxMemoryBytes = 1000;
    sandbox.createSandbox("plugin-a", limits);

    CHECK(sandbox.recordMemoryUsage("plugin-a", 500));
    CHECK(sandbox.getViolationCount("plugin-a") == 0);

    CHECK(sandbox.recordMemoryUsage("plugin-a", 2000));
    CHECK(sandbox.getViolationCount("plugin-a") == 1);
}

TEST_CASE("PluginSandbox - CPU usage tracking") {
    PluginSandbox sandbox;
    ResourceLimits limits;
    limits.maxCpuTimeMs = 1000;
    sandbox.createSandbox("plugin-a", limits);

    CHECK(sandbox.recordCpuUsage("plugin-a", 500));
    CHECK(sandbox.getViolationCount("plugin-a") == 0);

    CHECK(sandbox.recordCpuUsage("plugin-a", 2000));
    CHECK(sandbox.getViolationCount("plugin-a") == 1);
}

TEST_CASE("PluginSandbox - Fault isolation") {
    PluginSandbox sandbox;
    ResourceLimits limits;
    sandbox.createSandbox("plugin-a", limits);

    CHECK_FALSE(sandbox.isIsolated("plugin-a"));
    CHECK(sandbox.isolatePlugin("plugin-a"));
    CHECK(sandbox.isIsolated("plugin-a"));
    CHECK(sandbox.releasePlugin("plugin-a"));
    CHECK_FALSE(sandbox.isIsolated("plugin-a"));
}

TEST_CASE("PluginSandbox - API access restriction") {
    PluginSandbox sandbox;
    ResourceLimits limits;
    sandbox.createSandbox("plugin-a", limits);

    CHECK(sandbox.isApiAllowed("plugin-a", "readFile"));
    CHECK(sandbox.restrictApiAccess("plugin-a", {"writeFile", "execProcess"}));
    CHECK(sandbox.isApiAllowed("plugin-a", "readFile"));
    CHECK_FALSE(sandbox.isApiAllowed("plugin-a", "writeFile"));
    CHECK_FALSE(sandbox.isApiAllowed("plugin-a", "execProcess"));
}

TEST_CASE("PluginSandbox - Get status") {
    PluginSandbox sandbox;
    ResourceLimits limits;
    sandbox.createSandbox("plugin-a", limits);
    sandbox.recordMemoryUsage("plugin-a", 500);

    auto status = sandbox.getStatus("plugin-a");
    CHECK(status.pluginId == "plugin-a");
    CHECK(status.active);
    CHECK(status.memoryUsed == 500);
}

TEST_CASE("PluginSandbox - Active sandbox count") {
    PluginSandbox sandbox;
    ResourceLimits limits;
    sandbox.createSandbox("p1", limits);
    sandbox.createSandbox("p2", limits);
    CHECK(sandbox.getActiveSandboxCount() == 2);
}

TEST_CASE("PluginSandbox - Record violation") {
    PluginSandbox sandbox;
    ResourceLimits limits;
    sandbox.createSandbox("plugin-a", limits);

    CHECK(sandbox.recordViolation("plugin-a", "unauthorized_access"));
    CHECK(sandbox.getViolationCount("plugin-a") == 1);
}
