#include <doctest/doctest.h>
#include <telemetry/TelemetryManager.h>

using namespace ThreatOne::Telemetry;

TEST_CASE("MetricsCollector - Increment counter") {
    TelemetryManager mgr;
    auto& mc = mgr.getMetricsCollector();

    CHECK(mc.incrementCounter("requests_total"));
    CHECK(mc.incrementCounter("requests_total", 5.0));

    auto val = mc.getCounterValue("requests_total");
    REQUIRE(val.has_value());
    CHECK(val.value() == doctest::Approx(6.0));
}

TEST_CASE("MetricsCollector - Set gauge") {
    TelemetryManager mgr;
    auto& mc = mgr.getMetricsCollector();

    CHECK(mc.setGauge("cpu_usage", 75.0));
    auto val = mc.getGaugeValue("cpu_usage");
    REQUIRE(val.has_value());
    CHECK(val.value() == 75.0);

    mc.setGauge("cpu_usage", 80.0);
    val = mc.getGaugeValue("cpu_usage");
    CHECK(val.value() == 80.0);
}

TEST_CASE("MetricsCollector - Record histogram") {
    TelemetryManager mgr;
    auto& mc = mgr.getMetricsCollector();

    mc.recordHistogramValue("response_time", 5.0);
    mc.recordHistogramValue("response_time", 15.0);
    mc.recordHistogramValue("response_time", 75.0);

    auto buckets = mc.getHistogramBuckets("response_time");
    CHECK_FALSE(buckets.empty());
}

TEST_CASE("MetricsCollector - Record timer") {
    TelemetryManager mgr;
    auto& mc = mgr.getMetricsCollector();

    mc.recordTimerValue("scan_duration", 100.0);
    mc.recordTimerValue("scan_duration", 200.0);

    auto avg = mc.getAverageTimer("scan_duration");
    REQUIRE(avg.has_value());
    CHECK(avg.value() == doctest::Approx(150.0));
}

TEST_CASE("MetricsCollector - Get metric series") {
    TelemetryManager mgr;
    auto& mc = mgr.getMetricsCollector();

    mc.setGauge("temp", 20.0);
    mc.setGauge("temp", 25.0);
    mc.setGauge("temp", 30.0);

    auto series = mc.getMetricSeries("temp");
    REQUIRE(series.has_value());
    CHECK(series->count == 3);
    CHECK(series->min == 20.0);
    CHECK(series->max == 30.0);
}

TEST_CASE("MetricsCollector - Reset metrics") {
    TelemetryManager mgr;
    auto& mc = mgr.getMetricsCollector();

    mc.incrementCounter("test", 10.0);
    mc.resetMetrics();

    CHECK_FALSE(mc.getCounterValue("test").has_value());
    CHECK(mc.getMetrics().empty());
}

TEST_CASE("MetricsCollector - Statistics") {
    TelemetryManager mgr;
    auto& mc = mgr.getMetricsCollector();

    mc.incrementCounter("a");
    mc.setGauge("b", 1.0);
    mc.recordTimerValue("c", 100.0);

    CHECK(mc.getTotalMetricsRecorded() == 3);
    CHECK(mc.getUniqueMetricNames() == 3);
}
