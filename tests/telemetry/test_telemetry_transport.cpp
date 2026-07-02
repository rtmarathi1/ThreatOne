#include <doctest/doctest.h>
#include <telemetry/TelemetryManager.h>

using namespace ThreatOne::Telemetry;

TEST_CASE("TelemetryTransport - Enqueue events") {
    TelemetryManager mgr;
    auto& tt = mgr.getTelemetryTransport();

    TelemetryEvent event;
    event.name = "test_event";
    event.category = "test";

    CHECK(tt.enqueueEvent(event));
    CHECK(tt.getQueuedEventCount() == 1);
}

TEST_CASE("TelemetryTransport - Enqueue metrics") {
    TelemetryManager mgr;
    auto& tt = mgr.getTelemetryTransport();

    Metric metric;
    metric.name = "cpu_usage";
    metric.value = 75.0;

    CHECK(tt.enqueueMetric(metric));
    CHECK(tt.getQueuedMetricCount() == 1);
}

TEST_CASE("TelemetryTransport - Create batch") {
    TelemetryManager mgr;
    auto& tt = mgr.getTelemetryTransport();

    TelemetryEvent event;
    event.name = "e1";
    tt.enqueueEvent(event);
    tt.enqueueEvent(event);

    auto batchId = tt.createBatch();
    CHECK_FALSE(batchId.empty());
    CHECK(tt.getQueuedEventCount() == 0);

    auto batch = tt.getBatch(batchId);
    REQUIRE(batch.has_value());
    CHECK(batch->events.size() == 2);
}

TEST_CASE("TelemetryTransport - Flush batch") {
    TelemetryManager mgr;
    auto& tt = mgr.getTelemetryTransport();

    TelemetryEvent event;
    event.name = "e1";
    tt.enqueueEvent(event);

    auto batchId = tt.createBatch();
    CHECK(tt.flushBatch(batchId));
    CHECK(tt.getTotalBatchesSent() == 1);
}

TEST_CASE("TelemetryTransport - Disabled transport") {
    TelemetryManager mgr;
    auto& tt = mgr.getTelemetryTransport();

    tt.setEnabled(false);
    CHECK_FALSE(tt.isEnabled());
    CHECK(tt.getStatus() == TransportStatus::Disabled);

    TelemetryEvent event;
    event.name = "test";
    CHECK_FALSE(tt.enqueueEvent(event));
}

TEST_CASE("TelemetryTransport - Clear queue") {
    TelemetryManager mgr;
    auto& tt = mgr.getTelemetryTransport();

    TelemetryEvent event;
    event.name = "e1";
    tt.enqueueEvent(event);
    tt.enqueueEvent(event);

    tt.clearQueue();
    CHECK(tt.getQueuedEventCount() == 0);
}

TEST_CASE("TelemetryTransport - Empty batch creation fails") {
    TelemetryManager mgr;
    auto& tt = mgr.getTelemetryTransport();

    auto batchId = tt.createBatch();
    CHECK(batchId.empty());
}

TEST_CASE("TelemetryTransport - Statistics") {
    TelemetryManager mgr;
    auto& tt = mgr.getTelemetryTransport();

    TelemetryEvent event;
    event.name = "e1";
    tt.enqueueEvent(event);

    auto batchId = tt.createBatch();
    tt.flushBatch(batchId);

    auto stats = tt.getStats();
    CHECK(stats.totalBatchesSent == 1);
    CHECK(stats.totalEventsSent == 1);
}
