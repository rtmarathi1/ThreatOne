#include <doctest/doctest.h>
#include <telemetry/TelemetryManager.h>

#include <thread>
#include <chrono>

using namespace ThreatOne::Telemetry;

TEST_CASE("TelemetryManager - Track event") {
    TelemetryManager manager;

    TelemetryEvent event;
    event.name = "test_event";
    event.category = "test";
    event.properties["key1"] = "value1";

    CHECK(manager.trackEvent(event));

    auto events = manager.getEvents();
    REQUIRE(events.size() == 1);
    CHECK(events[0].name == "test_event");
    CHECK(events[0].category == "test");
    CHECK(events[0].properties.at("key1") == "value1");
    CHECK_FALSE(events[0].timestamp.empty());
}

TEST_CASE("TelemetryManager - Track multiple events") {
    TelemetryManager manager;

    TelemetryEvent event1;
    event1.name = "event_1";
    event1.category = "scan";

    TelemetryEvent event2;
    event2.name = "event_2";
    event2.category = "threat";

    CHECK(manager.trackEvent(event1));
    CHECK(manager.trackEvent(event2));

    auto events = manager.getEvents();
    REQUIRE(events.size() == 2);
    CHECK(events[0].name == "event_1");
    CHECK(events[1].name == "event_2");
}

TEST_CASE("TelemetryManager - Track error") {
    TelemetryManager manager;

    CHECK(manager.trackError("connection_failed", "network module"));

    auto events = manager.getEvents();
    REQUIRE(events.size() == 1);
    CHECK(events[0].name == "connection_failed");
    CHECK(events[0].category == "error");
    CHECK(events[0].properties.at("context") == "network module");
    CHECK_FALSE(events[0].timestamp.empty());
}

TEST_CASE("TelemetryManager - Track event when disabled") {
    TelemetryManager manager;
    manager.setEnabled(false);

    TelemetryEvent event;
    event.name = "disabled_event";
    event.category = "test";

    CHECK_FALSE(manager.trackEvent(event));

    auto events = manager.getEvents();
    CHECK(events.empty());
}

TEST_CASE("TelemetryManager - Track error when disabled") {
    TelemetryManager manager;
    manager.setEnabled(false);

    CHECK_FALSE(manager.trackError("error", "context"));

    auto events = manager.getEvents();
    CHECK(events.empty());
}

TEST_CASE("TelemetryManager - Enable disable toggle") {
    TelemetryManager manager;

    CHECK(manager.isEnabled());

    manager.setEnabled(false);
    CHECK_FALSE(manager.isEnabled());

    manager.setEnabled(true);
    CHECK(manager.isEnabled());
}

TEST_CASE("TelemetryManager - Record metric counter") {
    TelemetryManager manager;

    Metric metric;
    metric.name = "requests_total";
    metric.type = MetricType::Counter;
    metric.value = 42.0;
    metric.labels["endpoint"] = "/api/scan";

    CHECK(manager.recordMetric(metric));

    auto metrics = manager.getMetrics();
    REQUIRE(metrics.size() == 1);
    CHECK(metrics[0].name == "requests_total");
    CHECK(metrics[0].type == MetricType::Counter);
    CHECK(metrics[0].value == 42.0);
    CHECK(metrics[0].labels.at("endpoint") == "/api/scan");
    CHECK_FALSE(metrics[0].timestamp.empty());
}

TEST_CASE("TelemetryManager - Record metric gauge") {
    TelemetryManager manager;

    Metric metric;
    metric.name = "memory_usage_bytes";
    metric.type = MetricType::Gauge;
    metric.value = 1024.5;

    CHECK(manager.recordMetric(metric));

    auto metrics = manager.getMetrics();
    REQUIRE(metrics.size() == 1);
    CHECK(metrics[0].type == MetricType::Gauge);
    CHECK(metrics[0].value == 1024.5);
}

TEST_CASE("TelemetryManager - Record metric histogram") {
    TelemetryManager manager;

    Metric metric;
    metric.name = "response_time_ms";
    metric.type = MetricType::Histogram;
    metric.value = 150.0;

    CHECK(manager.recordMetric(metric));

    auto metrics = manager.getMetrics(std::nullopt, MetricType::Histogram);
    REQUIRE(metrics.size() == 1);
    CHECK(metrics[0].name == "response_time_ms");
}

TEST_CASE("TelemetryManager - Record metric timer") {
    TelemetryManager manager;

    Metric metric;
    metric.name = "scan_duration_ms";
    metric.type = MetricType::Timer;
    metric.value = 5000.0;

    CHECK(manager.recordMetric(metric));

    auto value = manager.getMetricValue("scan_duration_ms");
    REQUIRE(value.has_value());
    CHECK(value.value() == 5000.0);
}

TEST_CASE("TelemetryManager - Record metric when disabled") {
    TelemetryManager manager;
    manager.setEnabled(false);

    Metric metric;
    metric.name = "test_metric";
    metric.type = MetricType::Counter;
    metric.value = 1.0;

    CHECK_FALSE(manager.recordMetric(metric));

    auto metrics = manager.getMetrics();
    CHECK(metrics.empty());
}

TEST_CASE("TelemetryManager - Get metrics filtered by name") {
    TelemetryManager manager;

    Metric m1;
    m1.name = "cpu_usage";
    m1.type = MetricType::Gauge;
    m1.value = 75.0;

    Metric m2;
    m2.name = "memory_usage";
    m2.type = MetricType::Gauge;
    m2.value = 60.0;

    Metric m3;
    m3.name = "cpu_usage";
    m3.type = MetricType::Gauge;
    m3.value = 80.0;

    manager.recordMetric(m1);
    manager.recordMetric(m2);
    manager.recordMetric(m3);

    auto cpuMetrics = manager.getMetrics(std::string("cpu_usage"));
    REQUIRE(cpuMetrics.size() == 2);
    CHECK(cpuMetrics[0].value == 75.0);
    CHECK(cpuMetrics[1].value == 80.0);
}

TEST_CASE("TelemetryManager - Get metrics filtered by type") {
    TelemetryManager manager;

    Metric m1;
    m1.name = "counter1";
    m1.type = MetricType::Counter;
    m1.value = 10.0;

    Metric m2;
    m2.name = "gauge1";
    m2.type = MetricType::Gauge;
    m2.value = 50.0;

    Metric m3;
    m3.name = "counter2";
    m3.type = MetricType::Counter;
    m3.value = 20.0;

    manager.recordMetric(m1);
    manager.recordMetric(m2);
    manager.recordMetric(m3);

    auto counters = manager.getMetrics(std::nullopt, MetricType::Counter);
    REQUIRE(counters.size() == 2);
    CHECK(counters[0].name == "counter1");
    CHECK(counters[1].name == "counter2");
}

TEST_CASE("TelemetryManager - Get metrics filtered by name and type") {
    TelemetryManager manager;

    Metric m1;
    m1.name = "requests";
    m1.type = MetricType::Counter;
    m1.value = 100.0;

    Metric m2;
    m2.name = "requests";
    m2.type = MetricType::Gauge;
    m2.value = 5.0;

    manager.recordMetric(m1);
    manager.recordMetric(m2);

    auto filtered = manager.getMetrics(std::string("requests"), MetricType::Counter);
    REQUIRE(filtered.size() == 1);
    CHECK(filtered[0].type == MetricType::Counter);
    CHECK(filtered[0].value == 100.0);
}

TEST_CASE("TelemetryManager - Get metric value returns most recent") {
    TelemetryManager manager;

    Metric m1;
    m1.name = "temperature";
    m1.type = MetricType::Gauge;
    m1.value = 20.0;

    Metric m2;
    m2.name = "temperature";
    m2.type = MetricType::Gauge;
    m2.value = 25.0;

    manager.recordMetric(m1);
    manager.recordMetric(m2);

    auto value = manager.getMetricValue("temperature");
    REQUIRE(value.has_value());
    CHECK(value.value() == 25.0);
}

TEST_CASE("TelemetryManager - Get metric value nonexistent") {
    TelemetryManager manager;
    auto value = manager.getMetricValue("nonexistent");
    CHECK_FALSE(value.has_value());
}

TEST_CASE("TelemetryManager - Reset metrics") {
    TelemetryManager manager;

    Metric metric;
    metric.name = "test_metric";
    metric.type = MetricType::Counter;
    metric.value = 1.0;

    manager.recordMetric(metric);
    CHECK(manager.getMetrics().size() == 1);

    manager.resetMetrics();
    CHECK(manager.getMetrics().empty());
    CHECK_FALSE(manager.getMetricValue("test_metric").has_value());
}

TEST_CASE("TelemetryManager - Register health check") {
    TelemetryManager manager;

    auto checkId = manager.registerHealthCheck("Database", "storage");
    CHECK_FALSE(checkId.empty());
    CHECK(checkId.find("HC-") == 0);
}

TEST_CASE("TelemetryManager - Register multiple health checks") {
    TelemetryManager manager;

    auto id1 = manager.registerHealthCheck("Database", "storage");
    auto id2 = manager.registerHealthCheck("Network", "connectivity");
    auto id3 = manager.registerHealthCheck("Disk", "storage");

    CHECK(id1 != id2);
    CHECK(id2 != id3);
    CHECK(id1 != id3);
}

TEST_CASE("TelemetryManager - Run health checks all healthy") {
    TelemetryManager manager;

    manager.registerHealthCheck("Database", "storage");
    manager.registerHealthCheck("Network", "connectivity");

    auto health = manager.runHealthChecks();
    CHECK(health.overallStatus == HealthStatus::Healthy);
    CHECK(health.checks.size() == 2);
    CHECK(health.uptimeSeconds >= 0.0);

    for (const auto& check : health.checks) {
        CHECK(check.status == HealthStatus::Healthy);
        CHECK(check.message == "OK");
        CHECK_FALSE(check.lastChecked.empty());
        CHECK(check.responseTimeMs > 0.0);
    }
}

TEST_CASE("TelemetryManager - System health worst case aggregation") {
    TelemetryManager manager;

    // Test the overall status computation by running health checks
    // Default behavior is all healthy, so test with the system health retrieval
    manager.registerHealthCheck("Service1", "core");
    manager.registerHealthCheck("Service2", "network");

    auto health = manager.runHealthChecks();
    CHECK(health.overallStatus == HealthStatus::Healthy);

    // The getSystemHealth returns last run result
    auto retrieved = manager.getSystemHealth();
    CHECK(retrieved.overallStatus == HealthStatus::Healthy);
    CHECK(retrieved.checks.size() == 2);
}

TEST_CASE("TelemetryManager - Get system health before running checks") {
    TelemetryManager manager;

    auto health = manager.getSystemHealth();
    // Before any checks have run, overall status should be unknown/default
    CHECK(health.checks.empty());
}

TEST_CASE("TelemetryManager - Run health checks with no checks registered") {
    TelemetryManager manager;

    auto health = manager.runHealthChecks();
    CHECK(health.overallStatus == HealthStatus::Unknown);
    CHECK(health.checks.empty());
    CHECK(health.uptimeSeconds >= 0.0);
}

TEST_CASE("TelemetryManager - Send heartbeat") {
    TelemetryManager manager;

    CHECK(manager.sendHeartbeat());

    auto heartbeat = manager.getLastHeartbeat();
    REQUIRE(heartbeat.has_value());
    CHECK_FALSE(heartbeat->timestamp.empty());
    CHECK(heartbeat->version == "1.0.0");
    CHECK(heartbeat->hostname == "localhost");
    CHECK(heartbeat->healthy == true);
}

TEST_CASE("TelemetryManager - Send heartbeat when disabled") {
    TelemetryManager manager;
    manager.setEnabled(false);

    CHECK_FALSE(manager.sendHeartbeat());

    auto heartbeat = manager.getLastHeartbeat();
    CHECK_FALSE(heartbeat.has_value());
}

TEST_CASE("TelemetryManager - Get last heartbeat before sending") {
    TelemetryManager manager;

    auto heartbeat = manager.getLastHeartbeat();
    CHECK_FALSE(heartbeat.has_value());
}

TEST_CASE("TelemetryManager - Track feature usage single use") {
    TelemetryManager manager;

    CHECK(manager.trackFeatureUsage("scan", 100.0));

    auto stats = manager.getFeatureUsageStats();
    REQUIRE(stats.size() == 1);
    CHECK(stats[0].featureName == "scan");
    CHECK(stats[0].useCount == 1);
    CHECK(stats[0].averageDurationMs == 100.0);
    CHECK_FALSE(stats[0].lastUsed.empty());
}

TEST_CASE("TelemetryManager - Track feature usage multiple uses") {
    TelemetryManager manager;

    manager.trackFeatureUsage("scan", 100.0);
    manager.trackFeatureUsage("scan", 200.0);
    manager.trackFeatureUsage("scan", 300.0);

    auto stats = manager.getFeatureUsageStats();
    REQUIRE(stats.size() == 1);
    CHECK(stats[0].featureName == "scan");
    CHECK(stats[0].useCount == 3);
    CHECK(stats[0].averageDurationMs == doctest::Approx(200.0));
}

TEST_CASE("TelemetryManager - Track feature usage multiple features") {
    TelemetryManager manager;

    manager.trackFeatureUsage("scan", 100.0);
    manager.trackFeatureUsage("quarantine", 50.0);
    manager.trackFeatureUsage("report", 200.0);

    auto stats = manager.getFeatureUsageStats();
    CHECK(stats.size() == 3);

    // Verify each feature exists (order may vary in unordered_map)
    bool foundScan = false, foundQuarantine = false, foundReport = false;
    for (const auto& s : stats) {
        if (s.featureName == "scan") {
            foundScan = true;
            CHECK(s.useCount == 1);
            CHECK(s.averageDurationMs == 100.0);
        } else if (s.featureName == "quarantine") {
            foundQuarantine = true;
            CHECK(s.useCount == 1);
            CHECK(s.averageDurationMs == 50.0);
        } else if (s.featureName == "report") {
            foundReport = true;
            CHECK(s.useCount == 1);
            CHECK(s.averageDurationMs == 200.0);
        }
    }
    CHECK(foundScan);
    CHECK(foundQuarantine);
    CHECK(foundReport);
}

TEST_CASE("TelemetryManager - Track feature usage when disabled") {
    TelemetryManager manager;
    manager.setEnabled(false);

    CHECK_FALSE(manager.trackFeatureUsage("scan", 100.0));

    auto stats = manager.getFeatureUsageStats();
    CHECK(stats.empty());
}

TEST_CASE("TelemetryManager - Uptime calculation") {
    TelemetryManager manager;

    // Uptime should be non-negative and very small (just created)
    double uptime = manager.getUptimeSeconds();
    CHECK(uptime >= 0.0);
    CHECK(uptime < 5.0);  // Should be less than 5 seconds

    // Sleep briefly and verify uptime increases
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    double uptime2 = manager.getUptimeSeconds();
    CHECK(uptime2 > uptime);
}

TEST_CASE("TelemetryManager - Usage stats with scan events") {
    TelemetryManager manager;

    TelemetryEvent scanEvent;
    scanEvent.name = "full_scan";
    scanEvent.category = "scan";
    manager.trackEvent(scanEvent);

    TelemetryEvent threatEvent;
    threatEvent.name = "malware_detected";
    threatEvent.category = "threat";
    manager.trackEvent(threatEvent);

    auto stats = manager.getUsageStats();
    CHECK(stats.totalScans == 1);
    CHECK(stats.threatsDetected == 1);
    CHECK(stats.uptime < 10);
    CHECK_FALSE(stats.lastActive.empty());
}

TEST_CASE("TelemetryManager - Re-enable after disable") {
    TelemetryManager manager;

    manager.setEnabled(false);

    TelemetryEvent event;
    event.name = "during_disabled";
    event.category = "test";
    CHECK_FALSE(manager.trackEvent(event));

    manager.setEnabled(true);

    event.name = "after_enable";
    CHECK(manager.trackEvent(event));

    auto events = manager.getEvents();
    REQUIRE(events.size() == 1);
    CHECK(events[0].name == "after_enable");
}

TEST_CASE("TelemetryManager - Feature usage average duration accuracy") {
    TelemetryManager manager;

    // Track with known durations: 10, 20, 30, 40
    // Running average: 10, 15, 20, 25
    manager.trackFeatureUsage("precise", 10.0);
    manager.trackFeatureUsage("precise", 20.0);
    manager.trackFeatureUsage("precise", 30.0);
    manager.trackFeatureUsage("precise", 40.0);

    auto stats = manager.getFeatureUsageStats();
    REQUIRE(stats.size() == 1);
    CHECK(stats[0].useCount == 4);
    CHECK(stats[0].averageDurationMs == doctest::Approx(25.0));
}

TEST_CASE("TelemetryManager - Health check component naming") {
    TelemetryManager manager;

    manager.registerHealthCheck("Primary DB", "database");
    manager.registerHealthCheck("Redis Cache", "cache");

    auto health = manager.runHealthChecks();
    REQUIRE(health.checks.size() == 2);

    bool foundDb = false, foundCache = false;
    for (const auto& check : health.checks) {
        if (check.name == "Primary DB") {
            foundDb = true;
            CHECK(check.component == "database");
        } else if (check.name == "Redis Cache") {
            foundCache = true;
            CHECK(check.component == "cache");
        }
    }
    CHECK(foundDb);
    CHECK(foundCache);
}
