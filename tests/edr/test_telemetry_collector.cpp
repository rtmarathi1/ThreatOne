#include <doctest/doctest.h>
#include <edr/TelemetryCollector.h>

#include <chrono>

using namespace ThreatOne::EDR;

TEST_CASE("TelemetryCollector - collect system metrics") {
    TelemetryCollector collector;

    SUBCASE("First collection returns valid memory metrics") {
        auto data = collector.collectSystemMetrics();

        // Memory metrics should be non-zero on any Linux system
        CHECK(data.totalMemoryBytes > 0);
        CHECK(data.usedMemoryBytes > 0);
        CHECK(data.availableMemoryBytes > 0);
        CHECK(data.memoryUsagePercent > 0.0);
        CHECK(data.memoryUsagePercent <= 100.0);
    }

    SUBCASE("Second collection gives CPU metrics") {
        // First call establishes baseline
        (void)collector.collectSystemMetrics();

        // Second call can compute deltas
        auto data = collector.collectSystemMetrics();

        // CPU usage should be between 0 and 100
        CHECK(data.cpuUsagePercent >= 0.0);
        CHECK(data.cpuUsagePercent <= 100.0);
    }

    SUBCASE("Timestamp is populated") {
        auto data = collector.collectSystemMetrics();
        auto now = std::chrono::system_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(
            now - data.timestamp).count();
        CHECK(diff < 2); // Should be within 2 seconds
    }
}

TEST_CASE("TelemetryCollector - historical metrics") {
    TelemetryCollector collector(10);

    SUBCASE("Empty history initially") {
        auto history = collector.getHistoricalMetrics();
        CHECK(history.empty());
    }

    SUBCASE("History grows with collections") {
        (void)collector.collectSystemMetrics();
        (void)collector.collectSystemMetrics();
        (void)collector.collectSystemMetrics();

        auto history = collector.getHistoricalMetrics();
        CHECK(history.size() == 3);
    }

    SUBCASE("History respects window size") {
        for (int i = 0; i < 15; i++) {
            (void)collector.collectSystemMetrics();
        }

        auto history = collector.getHistoricalMetrics();
        CHECK(history.size() == 10); // Max history size
    }

    SUBCASE("Get subset of history") {
        for (int i = 0; i < 5; i++) {
            (void)collector.collectSystemMetrics();
        }

        auto subset = collector.getHistoricalMetrics(3);
        CHECK(subset.size() == 3);
    }

    SUBCASE("Clear history works") {
        TelemetryCollector freshCollector(10);
        TelemetryData d;
        d.cpuUsagePercent = 10.0;
        d.memoryUsagePercent = 50.0;
        d.timestamp = std::chrono::system_clock::now();
        freshCollector.injectMetrics(d);
        freshCollector.injectMetrics(d);
        auto histBefore = freshCollector.getHistoricalMetrics();
        REQUIRE(histBefore.size() == 2);

        freshCollector.clearHistory();
        auto histAfter = freshCollector.getHistoricalMetrics();
        CHECK(histAfter.empty());
    }
}

TEST_CASE("TelemetryCollector - anomaly detection") {
    TelemetryCollector collector(60);

    SUBCASE("Not enough data returns no anomalies") {
        (void)collector.collectSystemMetrics();
        auto anomalies = collector.detectAnomalies();
        CHECK(anomalies.empty());
    }

    SUBCASE("Injected spike triggers anomaly") {
        // Inject baseline data (low CPU usage)
        for (int i = 0; i < 10; i++) {
            TelemetryData data;
            data.cpuUsagePercent = 10.0;
            data.memoryUsagePercent = 50.0;
            data.diskReadBytes = 1000;
            data.diskWriteBytes = 500;
            data.networkRxBytes = 2000;
            data.networkTxBytes = 1000;
            data.timestamp = std::chrono::system_clock::now();
            collector.injectMetrics(data);
        }

        // Inject a spike
        TelemetryData spike;
        spike.cpuUsagePercent = 99.0;
        spike.memoryUsagePercent = 50.0;
        spike.diskReadBytes = 1000;
        spike.diskWriteBytes = 500;
        spike.networkRxBytes = 2000;
        spike.networkTxBytes = 1000;
        spike.timestamp = std::chrono::system_clock::now();
        collector.injectMetrics(spike);

        auto anomalies = collector.detectAnomalies();
        bool foundCpuAnomaly = false;
        for (const auto& a : anomalies) {
            if (a.metric == "cpu") {
                foundCpuAnomaly = true;
                CHECK(a.currentValue == doctest::Approx(99.0));
                CHECK(a.deviationFactor > 2.0);
            }
        }
        CHECK(foundCpuAnomaly);
    }

    SUBCASE("Stable metrics produce no anomalies") {
        // Inject stable data
        for (int i = 0; i < 10; i++) {
            TelemetryData data;
            data.cpuUsagePercent = 25.0;
            data.memoryUsagePercent = 60.0;
            data.diskReadBytes = 5000;
            data.diskWriteBytes = 3000;
            data.networkRxBytes = 10000;
            data.networkTxBytes = 8000;
            data.timestamp = std::chrono::system_clock::now();
            collector.injectMetrics(data);
        }

        auto anomalies = collector.detectAnomalies();
        CHECK(anomalies.empty());
    }

    SUBCASE("Anomaly severity is categorized") {
        // Inject baseline
        for (int i = 0; i < 10; i++) {
            TelemetryData data;
            data.cpuUsagePercent = 10.0;
            data.memoryUsagePercent = 50.0;
            data.diskReadBytes = 1000;
            data.diskWriteBytes = 500;
            data.networkRxBytes = 2000;
            data.networkTxBytes = 1000;
            data.timestamp = std::chrono::system_clock::now();
            collector.injectMetrics(data);
        }

        // Add moderate variation then a spike
        TelemetryData spike;
        spike.cpuUsagePercent = 95.0;
        spike.memoryUsagePercent = 50.0;
        spike.diskReadBytes = 1000;
        spike.diskWriteBytes = 500;
        spike.networkRxBytes = 2000;
        spike.networkTxBytes = 1000;
        spike.timestamp = std::chrono::system_clock::now();
        collector.injectMetrics(spike);

        auto anomalies = collector.detectAnomalies();
        for (const auto& a : anomalies) {
            CHECK((a.severity == "low" || a.severity == "medium" || a.severity == "high"));
        }
    }
}
