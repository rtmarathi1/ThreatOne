#include <doctest/doctest.h>
#include <monitor/ResourceTracker.h>

using namespace ThreatOne::Monitor;

TEST_CASE("ResourceTracker - Track process resources") {
    ResourceTracker tracker;

    ProcessResourceUsage usage;
    usage.pid = 1234;
    usage.name = "firefox";
    usage.cpuPercent = 25.0;
    usage.memoryBytes = 512 * 1024 * 1024;
    usage.threads = 32;

    tracker.updateProcessResource(usage);

    auto resources = tracker.getProcessResources();
    REQUIRE(resources.size() == 1);
    CHECK(resources[0].pid == 1234);
    CHECK(resources[0].name == "firefox");
    CHECK(tracker.getTrackedProcessCount() == 1);
}

TEST_CASE("ResourceTracker - Get specific process resource") {
    ResourceTracker tracker;

    ProcessResourceUsage usage;
    usage.pid = 100;
    usage.name = "test";
    tracker.updateProcessResource(usage);

    auto proc = tracker.getProcessResource(100);
    CHECK(proc.name == "test");

    auto missing = tracker.getProcessResource(999);
    CHECK(missing.pid == 0);
}

TEST_CASE("ResourceTracker - Remove process") {
    ResourceTracker tracker;

    ProcessResourceUsage usage;
    usage.pid = 100;
    usage.name = "test";
    tracker.updateProcessResource(usage);

    tracker.removeProcess(100);
    CHECK(tracker.getTrackedProcessCount() == 0);
}

TEST_CASE("ResourceTracker - Detect CPU resource hogs") {
    ResourceTracker tracker;
    tracker.setThreshold("cpu", 80.0);

    ProcessResourceUsage usage1;
    usage1.pid = 1;
    usage1.name = "cpu_hog";
    usage1.cpuPercent = 95.0;
    tracker.updateProcessResource(usage1);

    ProcessResourceUsage usage2;
    usage2.pid = 2;
    usage2.name = "normal";
    usage2.cpuPercent = 10.0;
    tracker.updateProcessResource(usage2);

    auto hogs = tracker.detectResourceHogs();
    REQUIRE(hogs.size() == 1);
    CHECK(hogs[0].name == "cpu_hog");
    CHECK(hogs[0].resource == "cpu");
}

TEST_CASE("ResourceTracker - Threshold management") {
    ResourceTracker tracker;

    tracker.setThreshold("cpu", 75.0);
    CHECK(tracker.getThreshold("cpu") == doctest::Approx(75.0));

    tracker.setThreshold("memory", 80.0);
    CHECK(tracker.getThreshold("memory") == doctest::Approx(80.0));

    CHECK(tracker.getThreshold("nonexistent") == doctest::Approx(0.0));
}

TEST_CASE("ResourceTracker - Memory leak detection") {
    ResourceTracker tracker;

    // Initial tracking
    tracker.trackMemoryGrowth(1, "leaky_app", 100 * 1024 * 1024);
    // Simulate growth over threshold (2x initial)
    tracker.trackMemoryGrowth(1, "leaky_app", 250 * 1024 * 1024);

    auto suspects = tracker.getMemoryLeakSuspects();
    REQUIRE(suspects.size() == 1);
    CHECK(suspects[0].name == "leaky_app");
    CHECK(suspects[0].currentMemory > suspects[0].initialMemory);
}

TEST_CASE("ResourceTracker - No memory leak for stable processes") {
    ResourceTracker tracker;

    tracker.trackMemoryGrowth(1, "stable_app", 100 * 1024 * 1024);
    tracker.trackMemoryGrowth(1, "stable_app", 105 * 1024 * 1024); // minor growth

    auto suspects = tracker.getMemoryLeakSuspects();
    CHECK(suspects.empty());
}

TEST_CASE("ResourceTracker - Clear memory tracking") {
    ResourceTracker tracker;
    tracker.trackMemoryGrowth(1, "app", 100);
    tracker.clearMemoryTracking();
    CHECK(tracker.getMemoryLeakSuspects().empty());
}

TEST_CASE("ResourceTracker - Top CPU consumers") {
    ResourceTracker tracker;

    for (int i = 1; i <= 5; ++i) {
        ProcessResourceUsage usage;
        usage.pid = static_cast<uint64_t>(i);
        usage.name = "proc" + std::to_string(i);
        usage.cpuPercent = static_cast<double>(i * 20);
        tracker.updateProcessResource(usage);
    }

    auto top = tracker.getTopCpuConsumers(3);
    REQUIRE(top.size() == 3);
    CHECK(top[0].cpuPercent >= top[1].cpuPercent);
    CHECK(top[1].cpuPercent >= top[2].cpuPercent);
}

TEST_CASE("ResourceTracker - Top memory consumers") {
    ResourceTracker tracker;

    for (int i = 1; i <= 5; ++i) {
        ProcessResourceUsage usage;
        usage.pid = static_cast<uint64_t>(i);
        usage.name = "proc" + std::to_string(i);
        usage.memoryBytes = static_cast<uint64_t>(i) * 1024 * 1024;
        tracker.updateProcessResource(usage);
    }

    auto top = tracker.getTopMemoryConsumers(2);
    REQUIRE(top.size() == 2);
    CHECK(top[0].memoryBytes >= top[1].memoryBytes);
}

TEST_CASE("ResourceTracker - Total memory used") {
    ResourceTracker tracker;

    ProcessResourceUsage u1;
    u1.pid = 1;
    u1.memoryBytes = 100;
    tracker.updateProcessResource(u1);

    ProcessResourceUsage u2;
    u2.pid = 2;
    u2.memoryBytes = 200;
    tracker.updateProcessResource(u2);

    CHECK(tracker.getTotalMemoryUsed() == 300);
}
