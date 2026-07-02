#include <doctest/doctest.h>
#include <telemetry/TelemetryManager.h>

using namespace ThreatOne::Telemetry;

TEST_CASE("DiagnosticsEngine - Register check") {
    TelemetryManager mgr;
    auto& de = mgr.getDiagnosticsEngine();

    auto id = de.registerCheck("Database", "storage");
    CHECK_FALSE(id.empty());
    CHECK(id.find("DIAG-") == 0);
    CHECK(de.getCheckCount() == 1);
}

TEST_CASE("DiagnosticsEngine - Run diagnostics") {
    TelemetryManager mgr;
    auto& de = mgr.getDiagnosticsEngine();

    de.registerCheck("DB", "storage");
    de.registerCheck("Network", "connectivity");

    auto report = de.runDiagnostics();
    CHECK(report.overallStatus == HealthStatus::Healthy);
    CHECK(report.checks.size() == 2);
    CHECK_FALSE(report.generatedAt.empty());
}

TEST_CASE("DiagnosticsEngine - Run single check") {
    TelemetryManager mgr;
    auto& de = mgr.getDiagnosticsEngine();

    auto id = de.registerCheck("Service", "core");
    CHECK(de.runSingleCheck(id));

    auto result = de.getCheckResult(id);
    REQUIRE(result.has_value());
    CHECK(result->status == HealthStatus::Healthy);
}

TEST_CASE("DiagnosticsEngine - System info") {
    TelemetryManager mgr;
    auto& de = mgr.getDiagnosticsEngine();

    SystemInfo info;
    info.osName = "Linux";
    info.osVersion = "5.15";
    info.hostname = "test-host";
    info.cpuCores = 4;
    de.setSystemInfo(info);

    auto retrieved = de.getSystemInfo();
    CHECK(retrieved.osName == "Linux");
    CHECK(retrieved.cpuCores == 4);
}

TEST_CASE("DiagnosticsEngine - Update check status") {
    TelemetryManager mgr;
    auto& de = mgr.getDiagnosticsEngine();

    auto id = de.registerCheck("Service", "core");
    de.updateCheckStatus(id, HealthStatus::Degraded, "High latency");

    auto result = de.getCheckResult(id);
    CHECK(result->status == HealthStatus::Degraded);
    CHECK(result->message == "High latency");
}

TEST_CASE("DiagnosticsEngine - Latest report") {
    TelemetryManager mgr;
    auto& de = mgr.getDiagnosticsEngine();

    CHECK_FALSE(de.getLatestReport().has_value());

    de.registerCheck("Test", "core");
    de.runDiagnostics();

    auto latest = de.getLatestReport();
    REQUIRE(latest.has_value());
    CHECK_FALSE(latest->id.empty());
}

TEST_CASE("DiagnosticsEngine - Unregister check") {
    TelemetryManager mgr;
    auto& de = mgr.getDiagnosticsEngine();

    auto id = de.registerCheck("Temp", "temp");
    CHECK(de.getCheckCount() == 1);
    CHECK(de.unregisterCheck(id));
    CHECK(de.getCheckCount() == 0);
}
