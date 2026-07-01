#include <doctest/doctest.h>
#include <network/BandwidthMonitor.h>

using namespace ThreatOne::Network;

TEST_CASE("BandwidthMonitor - initial state") {
    BandwidthMonitor monitor;
    auto stats = monitor.getStats();
    CHECK(stats.empty());

    auto total = monitor.getTotalStats();
    CHECK(total.bytesSent == 0);
    CHECK(total.bytesReceived == 0);
}

TEST_CASE("BandwidthMonitor - record traffic updates stats") {
    BandwidthMonitor monitor;
    monitor.recordTraffic("conn1", "/usr/bin/app", 1000, 2000);

    auto stats = monitor.getStats();
    REQUIRE(stats.count("conn1") == 1);
    CHECK(stats["conn1"].bytesSent == 1000);
    CHECK(stats["conn1"].bytesReceived == 2000);
    CHECK(stats["conn1"].appPath == "/usr/bin/app");
}

TEST_CASE("BandwidthMonitor - per-app stats accumulate") {
    BandwidthMonitor monitor;
    monitor.recordTraffic("conn1", "/usr/bin/browser", 500, 1000);
    monitor.recordTraffic("conn2", "/usr/bin/browser", 300, 700);

    auto appStats = monitor.getAppStats("/usr/bin/browser");
    CHECK(appStats.totalBytesSent == 800);
    CHECK(appStats.totalBytesReceived == 1700);
    CHECK(appStats.connectionCount == 2);
}

TEST_CASE("BandwidthMonitor - multiple connections accumulate on same ID") {
    BandwidthMonitor monitor;
    monitor.recordTraffic("conn1", "/usr/bin/app", 100, 200);
    monitor.recordTraffic("conn1", "/usr/bin/app", 300, 400);

    auto stats = monitor.getStats();
    CHECK(stats["conn1"].bytesSent == 400);
    CHECK(stats["conn1"].bytesReceived == 600);
}

TEST_CASE("BandwidthMonitor - total stats aggregate all connections") {
    BandwidthMonitor monitor;
    monitor.recordTraffic("conn1", "/app1", 100, 200);
    monitor.recordTraffic("conn2", "/app2", 300, 400);

    auto total = monitor.getTotalStats();
    CHECK(total.bytesSent == 400);
    CHECK(total.bytesReceived == 600);
}

TEST_CASE("BandwidthMonitor - rate limiting setup") {
    BandwidthMonitor monitor;
    monitor.setRateLimit("/usr/bin/app", 1024);

    // Under limit should pass
    CHECK(monitor.checkRateLimit("/usr/bin/app", 512));
}

TEST_CASE("BandwidthMonitor - rate limiting denies over-limit traffic") {
    BandwidthMonitor monitor;
    monitor.setRateLimit("/usr/bin/app", 1000);

    // Over limit should be denied
    CHECK_FALSE(monitor.checkRateLimit("/usr/bin/app", 2000));
}

TEST_CASE("BandwidthMonitor - no rate limit means allowed") {
    BandwidthMonitor monitor;
    // No rate limit set for this app
    CHECK(monitor.checkRateLimit("/usr/bin/unlimited", 999999));
}

TEST_CASE("BandwidthMonitor - reset clears all data") {
    BandwidthMonitor monitor;
    monitor.recordTraffic("conn1", "/app", 100, 200);
    monitor.reset();

    auto stats = monitor.getStats();
    CHECK(stats.empty());

    auto total = monitor.getTotalStats();
    CHECK(total.bytesSent == 0);
    CHECK(total.bytesReceived == 0);
}

TEST_CASE("BandwidthMonitor - app stats for non-existent app") {
    BandwidthMonitor monitor;
    auto appStats = monitor.getAppStats("/no/such/app");
    CHECK(appStats.totalBytesSent == 0);
    CHECK(appStats.totalBytesReceived == 0);
    CHECK(appStats.connectionCount == 0);
}
