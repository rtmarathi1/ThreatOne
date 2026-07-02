#include <doctest/doctest.h>
#include <monitor/HealthChecker.h>

using namespace ThreatOne::Monitor;

TEST_CASE("HealthChecker - Add health check") {
    HealthChecker checker;

    HealthCheck check;
    check.name = "Database";
    check.component = "database";
    check.description = "Check database connectivity";
    check.intervalSeconds = 30;

    auto id = checker.addHealthCheck(check);
    CHECK_FALSE(id.empty());

    auto checks = checker.getHealthChecks();
    CHECK(checks.size() == 1);
    CHECK(checks[0].name == "Database");
}

TEST_CASE("HealthChecker - Add health check empty name fails") {
    HealthChecker checker;
    HealthCheck check;
    check.name = "";
    CHECK(checker.addHealthCheck(check).empty());
}

TEST_CASE("HealthChecker - Remove health check") {
    HealthChecker checker;
    HealthCheck check;
    check.name = "Test";
    auto id = checker.addHealthCheck(check);

    CHECK(checker.removeHealthCheck(id));
    CHECK_FALSE(checker.removeHealthCheck("nonexistent"));
    CHECK(checker.getHealthChecks().empty());
}

TEST_CASE("HealthChecker - Enable and disable checks") {
    HealthChecker checker;
    HealthCheck check;
    check.name = "Test";
    check.enabled = true;
    auto id = checker.addHealthCheck(check);

    CHECK(checker.disableCheck(id));
    CHECK(checker.enableCheck(id));
    CHECK_FALSE(checker.enableCheck("invalid"));
    CHECK_FALSE(checker.disableCheck("invalid"));
}

TEST_CASE("HealthChecker - Run all checks") {
    HealthChecker checker;

    HealthCheck check1;
    check1.name = "Service A";
    check1.component = "service_a";
    checker.addHealthCheck(check1);

    HealthCheck check2;
    check2.name = "Service B";
    check2.component = "service_b";
    checker.addHealthCheck(check2);

    auto results = checker.runAllChecks();
    CHECK(results.size() == 2);

    for (const auto& result : results) {
        CHECK(result.status == HealthStatus::Healthy);
        CHECK_FALSE(result.checkedAt.empty());
    }
}

TEST_CASE("HealthChecker - Disabled checks are skipped") {
    HealthChecker checker;

    HealthCheck check;
    check.name = "Disabled";
    check.enabled = false;
    checker.addHealthCheck(check);

    auto results = checker.runAllChecks();
    CHECK(results.empty());
}

TEST_CASE("HealthChecker - Run single check") {
    HealthChecker checker;

    HealthCheck check;
    check.name = "Single";
    check.component = "test";
    auto id = checker.addHealthCheck(check);

    auto result = checker.runCheck(id);
    CHECK(result.name == "Single");
    CHECK(result.status == HealthStatus::Healthy);
}

TEST_CASE("HealthChecker - Overall health") {
    HealthChecker checker;

    HealthCheck check1;
    check1.name = "Check1";
    check1.component = "comp1";
    checker.addHealthCheck(check1);

    HealthCheck check2;
    check2.name = "Check2";
    check2.component = "comp2";
    checker.addHealthCheck(check2);

    checker.runAllChecks();

    auto overall = checker.getOverallHealth();
    CHECK(overall.status == HealthStatus::Healthy);
    CHECK(overall.totalChecks == 2);
    CHECK(overall.healthyCount == 2);
}

TEST_CASE("HealthChecker - Component health") {
    HealthChecker checker;

    HealthCheck check;
    check.name = "DB Check";
    check.component = "database";
    checker.addHealthCheck(check);

    checker.runAllChecks();

    CHECK(checker.getComponentHealth("database") == HealthStatus::Healthy);
    CHECK(checker.getComponentHealth("unknown") == HealthStatus::Unknown);
}

TEST_CASE("HealthChecker - Total checks counter") {
    HealthChecker checker;

    HealthCheck check;
    check.name = "Test";
    check.component = "test";
    auto id = checker.addHealthCheck(check);

    checker.runCheck(id);
    checker.runAllChecks();

    CHECK(checker.getTotalChecksRun() == 2);
}
