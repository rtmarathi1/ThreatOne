#include <doctest/doctest.h>
#include <telemetry/TelemetryManager.h>

using namespace ThreatOne::Telemetry;

TEST_CASE("UsageAnalytics - Start and end session") {
    TelemetryManager mgr;
    auto& ua = mgr.getUsageAnalytics();

    auto id = ua.startSession();
    CHECK_FALSE(id.empty());
    CHECK(ua.getActiveSesionCount() == 1);

    CHECK(ua.endSession(id));
    CHECK(ua.getActiveSesionCount() == 0);
}

TEST_CASE("UsageAnalytics - Track feature usage") {
    TelemetryManager mgr;
    auto& ua = mgr.getUsageAnalytics();

    CHECK(ua.trackFeatureUsage("scan", 100.0));
    CHECK(ua.trackFeatureUsage("scan", 200.0));
    CHECK(ua.trackFeatureUsage("quarantine", 50.0));

    auto stats = ua.getFeatureUsageStats();
    CHECK(stats.size() == 2);

    auto analytics = ua.getFeatureAnalytics("scan");
    REQUIRE(analytics.has_value());
    CHECK(analytics->totalUses == 2);
    CHECK(analytics->averageDurationMs == doctest::Approx(150.0));
}

TEST_CASE("UsageAnalytics - Most used features") {
    TelemetryManager mgr;
    auto& ua = mgr.getUsageAnalytics();

    ua.trackFeatureUsage("scan", 100.0);
    ua.trackFeatureUsage("scan", 100.0);
    ua.trackFeatureUsage("scan", 100.0);
    ua.trackFeatureUsage("report", 50.0);

    auto top = ua.getMostUsedFeatures(1);
    CHECK(top.size() == 1);
    CHECK(top[0] == "scan");
}

TEST_CASE("UsageAnalytics - Workflow tracking") {
    TelemetryManager mgr;
    auto& ua = mgr.getUsageAnalytics();

    auto sessionId = ua.startSession();
    ua.recordWorkflowStep(sessionId, "scan", "start", 10.0);
    ua.recordWorkflowStep(sessionId, "scan", "complete", 5000.0);

    auto steps = ua.getWorkflowSteps(sessionId);
    CHECK(steps.size() == 2);

    auto session = ua.getSession(sessionId);
    CHECK(session->actionsPerformed == 2);
}

TEST_CASE("UsageAnalytics - Session statistics") {
    TelemetryManager mgr;
    auto& ua = mgr.getUsageAnalytics();

    ua.startSession();
    ua.startSession();
    CHECK(ua.getTotalSessions() == 2);
}
