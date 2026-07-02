#include <doctest/doctest.h>
#include <telemetry/TelemetryManager.h>

using namespace ThreatOne::Telemetry;

TEST_CASE("CrashReporter - Report crash") {
    TelemetryManager mgr;
    auto& cr = mgr.getCrashReporter();

    auto id = cr.reportCrash("Scanner", "Segmentation fault", "main()\\nscanner_run()", true);
    CHECK_FALSE(id.empty());
    CHECK(id.find("CRASH-") == 0);

    auto report = cr.getCrashReport(id);
    REQUIRE(report.has_value());
    CHECK(report->component == "Scanner");
    CHECK(report->errorMessage == "Segmentation fault");
    CHECK(report->fatal == true);
}

TEST_CASE("CrashReporter - Report exception") {
    TelemetryManager mgr;
    auto& cr = mgr.getCrashReporter();

    auto id = cr.reportException("Network", "std::runtime_error", "Connection refused");
    CHECK_FALSE(id.empty());

    auto report = cr.getCrashReport(id);
    REQUIRE(report.has_value());
    CHECK(report->fatal == false);
    CHECK(report->errorMessage.find("std::runtime_error") != std::string::npos);
}

TEST_CASE("CrashReporter - System state capture") {
    TelemetryManager mgr;
    auto& cr = mgr.getCrashReporter();

    cr.setSystemState("running:idle");
    CHECK(cr.getSystemState() == "running:idle");

    cr.reportCrash("Core", "Error", "trace", false);
    auto reports = cr.getCrashReports();
    CHECK(reports.back().systemState == "running:idle");
}

TEST_CASE("CrashReporter - Get by component") {
    TelemetryManager mgr;
    auto& cr = mgr.getCrashReporter();

    cr.reportCrash("Scanner", "Error 1", "", false);
    cr.reportCrash("Network", "Error 2", "", false);
    cr.reportCrash("Scanner", "Error 3", "", true);

    auto scannerCrashes = cr.getCrashReportsByComponent("Scanner");
    CHECK(scannerCrashes.size() == 2);
}

TEST_CASE("CrashReporter - Fatal crashes filter") {
    TelemetryManager mgr;
    auto& cr = mgr.getCrashReporter();

    cr.reportCrash("A", "e1", "", true);
    cr.reportCrash("B", "e2", "", false);
    cr.reportCrash("C", "e3", "", true);

    auto fatal = cr.getFatalCrashes();
    CHECK(fatal.size() == 2);
}

TEST_CASE("CrashReporter - Statistics") {
    TelemetryManager mgr;
    auto& cr = mgr.getCrashReporter();

    cr.reportCrash("A", "e1", "", true);
    cr.reportCrash("A", "e2", "", false);
    cr.reportCrash("B", "e3", "", false);

    auto stats = cr.getStatistics();
    CHECK(stats.totalCrashes == 3);
    CHECK(stats.fatalCrashes == 1);
    CHECK(stats.nonFatalCrashes == 2);
    CHECK(stats.mostCrashedComponent == "A");
}

TEST_CASE("CrashReporter - Delete and clear") {
    TelemetryManager mgr;
    auto& cr = mgr.getCrashReporter();

    auto id = cr.reportCrash("X", "e", "", false);
    CHECK(cr.getCrashCount() == 1);
    CHECK(cr.deleteCrashReport(id));
    CHECK(cr.getCrashCount() == 0);

    cr.reportCrash("Y", "e2", "", false);
    cr.clearCrashReports();
    CHECK(cr.getCrashCount() == 0);
}
