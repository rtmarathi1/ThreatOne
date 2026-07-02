#include <doctest/doctest.h>
#include <plugin/DependencyResolver.h>

using namespace ThreatOne::Plugin;

TEST_CASE("DependencyResolver - Register and get manifest") {
    DependencyResolver resolver;

    PluginManifest manifest;
    manifest.id = "plugin_a";
    manifest.name = "Plugin A";
    manifest.version = "1.0.0";
    resolver.registerManifest(manifest);

    CHECK(resolver.hasManifest("plugin_a"));
    auto m = resolver.getManifest("plugin_a");
    CHECK(m.name == "Plugin A");
}

TEST_CASE("DependencyResolver - Resolve simple chain") {
    DependencyResolver resolver;

    PluginManifest mA;
    mA.id = "plugin_a"; mA.name = "A"; mA.version = "1.0.0";
    resolver.registerManifest(mA);

    PluginManifest mB;
    mB.id = "plugin_b"; mB.name = "B"; mB.version = "1.0.0";
    mB.dependencies.push_back({"plugin_a", "1.0.0", true});
    resolver.registerManifest(mB);

    PluginManifest mC;
    mC.id = "plugin_c"; mC.name = "C"; mC.version = "1.0.0";
    mC.dependencies.push_back({"plugin_b", "1.0.0", true});
    resolver.registerManifest(mC);

    auto deps = resolver.resolve("plugin_c");
    CHECK(deps.size() == 2);
    CHECK(deps[0] == "plugin_a");
    CHECK(deps[1] == "plugin_b");
}

TEST_CASE("DependencyResolver - No manifest returns empty") {
    DependencyResolver resolver;
    auto deps = resolver.resolve("nonexistent");
    CHECK(deps.empty());
}

TEST_CASE("DependencyResolver - Missing dependency detection") {
    DependencyResolver resolver;

    PluginManifest manifest;
    manifest.id = "plugin_with_dep";
    manifest.name = "Plugin";
    manifest.version = "1.0.0";
    manifest.dependencies.push_back({"missing_plugin", "1.0.0", true});
    resolver.registerManifest(manifest);

    auto deps = resolver.resolve("plugin_with_dep");
    CHECK(deps.size() == 1);
    CHECK(deps[0] == "MISSING:missing_plugin");
}

TEST_CASE("DependencyResolver - Direct dependencies") {
    DependencyResolver resolver;

    PluginManifest mA;
    mA.id = "dep_a"; mA.name = "A"; mA.version = "1.0.0";
    resolver.registerManifest(mA);

    PluginManifest mB;
    mB.id = "dep_b"; mB.name = "B"; mB.version = "1.0.0";
    mB.dependencies.push_back({"dep_a", "1.0.0", true});
    resolver.registerManifest(mB);

    auto direct = resolver.getDirectDependencies("dep_b");
    CHECK(direct.size() == 1);
    CHECK(direct[0].pluginId == "dep_a");
    CHECK(direct[0].satisfied);
}

TEST_CASE("DependencyResolver - Reverse dependencies") {
    DependencyResolver resolver;

    PluginManifest mA;
    mA.id = "base"; mA.name = "Base"; mA.version = "1.0.0";
    resolver.registerManifest(mA);

    PluginManifest mB;
    mB.id = "child_1"; mB.name = "Child 1"; mB.version = "1.0.0";
    mB.dependencies.push_back({"base", "1.0.0", true});
    resolver.registerManifest(mB);

    PluginManifest mC;
    mC.id = "child_2"; mC.name = "Child 2"; mC.version = "1.0.0";
    mC.dependencies.push_back({"base", "1.0.0", true});
    resolver.registerManifest(mC);

    auto reverse = resolver.getReverseDependencies("base");
    CHECK(reverse.size() == 2);
}

TEST_CASE("DependencyResolver - Are dependencies satisfied") {
    DependencyResolver resolver;

    PluginManifest mA;
    mA.id = "dep_a"; mA.name = "A"; mA.version = "1.0.0";
    resolver.registerManifest(mA);

    PluginManifest mB;
    mB.id = "needs_a"; mB.name = "B"; mB.version = "1.0.0";
    mB.dependencies.push_back({"dep_a", "1.0.0", true});
    resolver.registerManifest(mB);

    CHECK(resolver.areDependenciesSatisfied("needs_a", {"dep_a"}));
    CHECK_FALSE(resolver.areDependenciesSatisfied("needs_a", {}));
}

TEST_CASE("DependencyResolver - Version constraint") {
    DependencyResolver resolver;
    CHECK(resolver.versionSatisfiesConstraint("2.0.0", "1.0.0"));
    CHECK(resolver.versionSatisfiesConstraint("1.0.0", "1.0.0"));
    CHECK_FALSE(resolver.versionSatisfiesConstraint("0.9.0", "1.0.0"));
    CHECK(resolver.versionSatisfiesConstraint("1.0.0", ""));
}

TEST_CASE("DependencyResolver - Manifest count") {
    DependencyResolver resolver;
    PluginManifest m1; m1.id = "p1"; m1.name = "P1"; m1.version = "1.0.0";
    PluginManifest m2; m2.id = "p2"; m2.name = "P2"; m2.version = "1.0.0";
    resolver.registerManifest(m1);
    resolver.registerManifest(m2);
    CHECK(resolver.getManifestCount() == 2);
}

TEST_CASE("DependencyResolver - Unregister manifest") {
    DependencyResolver resolver;
    PluginManifest m; m.id = "plugin"; m.name = "P"; m.version = "1.0.0";
    resolver.registerManifest(m);
    CHECK(resolver.hasManifest("plugin"));
    resolver.unregisterManifest("plugin");
    CHECK_FALSE(resolver.hasManifest("plugin"));
}
