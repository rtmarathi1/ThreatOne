#include <doctest/doctest.h>
#include <monitor/SystemMonitor.h>

using namespace ThreatOne::Monitor;

TEST_CASE("SystemMonitor - Get system info") {
    SystemMonitor sysmon;

    auto info = sysmon.getSystemInfo();
    CHECK_FALSE(info.hostname.empty());
    CHECK_FALSE(info.osName.empty());
    CHECK_FALSE(info.architecture.empty());
}

TEST_CASE("SystemMonitor - Get uptime") {
    SystemMonitor sysmon;
    CHECK(sysmon.getUptime() > 0);
}

TEST_CASE("SystemMonitor - Get hostname") {
    SystemMonitor sysmon;
    CHECK_FALSE(sysmon.getHostname().empty());
}

TEST_CASE("SystemMonitor - Add and get loaded modules") {
    SystemMonitor sysmon;

    LoadedModule mod;
    mod.name = "test_module";
    mod.version = "1.0";
    mod.size = 4096;
    mod.status = "active";

    sysmon.addLoadedModule(mod);

    auto modules = sysmon.getLoadedModules();
    REQUIRE(modules.size() == 1);
    CHECK(modules[0].name == "test_module");
    CHECK(modules[0].version == "1.0");
    CHECK(sysmon.getModuleCount() == 1);
}

TEST_CASE("SystemMonitor - Duplicate modules not added") {
    SystemMonitor sysmon;

    LoadedModule mod;
    mod.name = "duplicate";
    mod.version = "1.0";

    sysmon.addLoadedModule(mod);
    sysmon.addLoadedModule(mod);

    CHECK(sysmon.getModuleCount() == 1);
}

TEST_CASE("SystemMonitor - Remove module") {
    SystemMonitor sysmon;

    LoadedModule mod;
    mod.name = "removable";
    sysmon.addLoadedModule(mod);

    CHECK(sysmon.removeModule("removable"));
    CHECK_FALSE(sysmon.removeModule("nonexistent"));
    CHECK(sysmon.getModuleCount() == 0);
}

TEST_CASE("SystemMonitor - Refresh system info") {
    SystemMonitor sysmon;
    CHECK(sysmon.refreshSystemInfo());
    CHECK_FALSE(sysmon.getHostname().empty());
}

TEST_CASE("SystemMonitor - System health") {
    SystemMonitor sysmon;
    CHECK(sysmon.isSystemHealthy());
}
