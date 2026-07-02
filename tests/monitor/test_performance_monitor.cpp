#include <doctest/doctest.h>
#include <monitor/PerformanceMonitor.h>

using namespace ThreatOne::Monitor;

TEST_CASE("PerformanceMonitor - Add and get sample") {
    PerformanceMonitor perfmon;

    PerformanceSample sample;
    sample.cpuUsage = 45.5;
    sample.memoryUsage = 60.2;
    sample.diskReadRate = 100.0;
    sample.diskWriteRate = 50.0;
    sample.gpuUsage = 30.0;

    perfmon.addSample(sample);

    auto latest = perfmon.getLatestSample();
    CHECK(latest.cpuUsage == doctest::Approx(45.5));
    CHECK(latest.memoryUsage == doctest::Approx(60.2));
}

TEST_CASE("PerformanceMonitor - Get recent samples") {
    PerformanceMonitor perfmon;

    for (int i = 0; i < 10; ++i) {
        PerformanceSample sample;
        sample.cpuUsage = static_cast<double>(i * 10);
        perfmon.addSample(sample);
    }

    auto recent = perfmon.getRecentSamples(5);
    CHECK(recent.size() == 5);
    CHECK(recent.back().cpuUsage == doctest::Approx(90.0));
}

TEST_CASE("PerformanceMonitor - Peak detection") {
    PerformanceMonitor perfmon;

    PerformanceSample s1;
    s1.cpuUsage = 30.0;
    s1.memoryUsage = 50.0;
    perfmon.addSample(s1);

    PerformanceSample s2;
    s2.cpuUsage = 95.0;
    s2.memoryUsage = 80.0;
    perfmon.addSample(s2);

    PerformanceSample s3;
    s3.cpuUsage = 40.0;
    s3.memoryUsage = 60.0;
    perfmon.addSample(s3);

    auto peaks = perfmon.getPeaks();
    CHECK(peaks.peakCpu == doctest::Approx(95.0));
    CHECK(peaks.peakMemory == doctest::Approx(80.0));
}

TEST_CASE("PerformanceMonitor - Current values") {
    PerformanceMonitor perfmon;

    PerformanceSample sample;
    sample.cpuUsage = 55.0;
    sample.memoryUsage = 70.0;
    sample.diskReadRate = 200.0;
    sample.diskWriteRate = 100.0;
    perfmon.addSample(sample);

    CHECK(perfmon.getCurrentCpuUsage() == doctest::Approx(55.0));
    CHECK(perfmon.getCurrentMemoryUsage() == doctest::Approx(70.0));
    CHECK(perfmon.getCurrentDiskUsage() == doctest::Approx(300.0));
}

TEST_CASE("PerformanceMonitor - Empty state") {
    PerformanceMonitor perfmon;

    CHECK(perfmon.getCurrentCpuUsage() == doctest::Approx(0.0));
    CHECK(perfmon.getCurrentMemoryUsage() == doctest::Approx(0.0));

    auto latest = perfmon.getLatestSample();
    CHECK(latest.cpuUsage == doctest::Approx(0.0));
}

TEST_CASE("PerformanceMonitor - Sampling interval") {
    PerformanceMonitor perfmon;

    CHECK(perfmon.getSamplingInterval() == 1000);
    perfmon.setSamplingInterval(5000);
    CHECK(perfmon.getSamplingInterval() == 5000);
}

TEST_CASE("PerformanceMonitor - Max samples cap") {
    PerformanceMonitor perfmon;
    perfmon.setMaxSamples(5);

    for (int i = 0; i < 10; ++i) {
        PerformanceSample sample;
        sample.cpuUsage = static_cast<double>(i);
        perfmon.addSample(sample);
    }

    auto recent = perfmon.getRecentSamples(100);
    CHECK(recent.size() == 5);
}

TEST_CASE("PerformanceMonitor - Total samples collected") {
    PerformanceMonitor perfmon;
    CHECK(perfmon.getTotalSamplesCollected() == 0);

    PerformanceSample sample;
    perfmon.addSample(sample);
    perfmon.addSample(sample);
    CHECK(perfmon.getTotalSamplesCollected() == 2);
}

TEST_CASE("PerformanceMonitor - Clear samples") {
    PerformanceMonitor perfmon;

    PerformanceSample sample;
    sample.cpuUsage = 50.0;
    perfmon.addSample(sample);

    perfmon.clearSamples();
    CHECK(perfmon.getRecentSamples(10).empty());
}
