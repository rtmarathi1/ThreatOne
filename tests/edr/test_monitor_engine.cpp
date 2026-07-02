#include <doctest/doctest.h>
#include <monitor/MonitorEngine.h>
#include <edr/EDREngine.h>

#include <memory>
#include <vector>

using namespace ThreatOne::Monitor;

TEST_CASE("MonitorEngine - start and stop monitoring") {
    auto edrEngine = std::make_shared<ThreatOne::EDR::EDREngine>();
    MonitorEngine engine(edrEngine);

    SUBCASE("Start monitoring for each type") {
        CHECK(engine.startMonitoring(MonitorType::Process));
        CHECK(engine.startMonitoring(MonitorType::File));
        CHECK(engine.startMonitoring(MonitorType::Registry));
        CHECK(engine.startMonitoring(MonitorType::Network));
        CHECK(engine.startMonitoring(MonitorType::Memory));
        CHECK(engine.startMonitoring(MonitorType::Performance));
    }

    SUBCASE("Stop monitoring for each type") {
        engine.startMonitoring(MonitorType::Process);
        engine.startMonitoring(MonitorType::File);

        CHECK(engine.stopMonitoring(MonitorType::Process));
        CHECK(engine.stopMonitoring(MonitorType::File));
    }

    SUBCASE("Start monitoring is idempotent") {
        CHECK(engine.startMonitoring(MonitorType::Process));
        CHECK(engine.startMonitoring(MonitorType::Process));
    }

    SUBCASE("Stop monitoring for inactive type succeeds") {
        CHECK(engine.stopMonitoring(MonitorType::Network));
    }
}

TEST_CASE("MonitorEngine - isMonitoring") {
    auto edrEngine = std::make_shared<ThreatOne::EDR::EDREngine>();
    MonitorEngine engine(edrEngine);

    SUBCASE("Not monitoring before start") {
        CHECK_FALSE(engine.isMonitoring(MonitorType::Process));
        CHECK_FALSE(engine.isMonitoring(MonitorType::File));
    }

    SUBCASE("isMonitoring reflects state after start/stop") {
        engine.startMonitoring(MonitorType::Process);
        CHECK(engine.isMonitoring(MonitorType::Process));
        CHECK_FALSE(engine.isMonitoring(MonitorType::File));

        engine.stopMonitoring(MonitorType::Process);
        CHECK_FALSE(engine.isMonitoring(MonitorType::Process));
    }
}

TEST_CASE("MonitorEngine - getMetrics returns valid data") {
    auto edrEngine = std::make_shared<ThreatOne::EDR::EDREngine>();
    MonitorEngine engine(edrEngine);
    engine.startMonitoring(MonitorType::Performance);

    SUBCASE("Metrics contain real system data") {
        auto metrics = engine.getMetrics();

        // Memory usage should be non-zero on any running system
        CHECK(metrics.memoryUsage > 0.0);

        // Process count should be at least 1 (our own process)
        CHECK(metrics.processCount > 0);
    }
}

TEST_CASE("MonitorEngine - warning threshold breach generates alert") {
    auto edrEngine = std::make_shared<ThreatOne::EDR::EDREngine>();
    MonitorEngine engine(edrEngine);
    engine.startMonitoring(MonitorType::Performance);

    // Set a very low warning threshold that will definitely be breached
    std::vector<MonitorThreshold> thresholds;
    MonitorThreshold t;
    t.type = MonitorType::Memory;
    t.warningLevel = 0.001;   // 0.001% - any system will exceed this
    t.criticalLevel = 99999.0; // Won't breach critical
    thresholds.push_back(t);

    CHECK(engine.setThresholds(thresholds));

    // Getting metrics triggers threshold check
    engine.getMetrics();

    auto alerts = engine.getAlerts();
    CHECK(!alerts.empty());
    if (!alerts.empty()) {
        CHECK(alerts[0].severity == "warning");
        CHECK(alerts[0].type == MonitorType::Memory);
    }
}

TEST_CASE("MonitorEngine - critical threshold breach generates alert") {
    auto edrEngine = std::make_shared<ThreatOne::EDR::EDREngine>();
    MonitorEngine engine(edrEngine);
    engine.startMonitoring(MonitorType::Performance);

    std::vector<MonitorThreshold> thresholds;
    MonitorThreshold t;
    t.type = MonitorType::Memory;
    t.warningLevel = 0.0;     // Disabled
    t.criticalLevel = 0.001;  // 0.001% - any system will exceed this
    thresholds.push_back(t);

    CHECK(engine.setThresholds(thresholds));

    engine.getMetrics();

    auto alerts = engine.getAlerts();
    CHECK(!alerts.empty());
    if (!alerts.empty()) {
        CHECK(alerts[0].severity == "critical");
    }
}

TEST_CASE("MonitorEngine - no alert when below thresholds") {
    auto edrEngine = std::make_shared<ThreatOne::EDR::EDREngine>();
    MonitorEngine engine(edrEngine);
    engine.startMonitoring(MonitorType::Performance);

    std::vector<MonitorThreshold> thresholds;
    MonitorThreshold t;
    t.type = MonitorType::Memory;
    t.warningLevel = 99999.0;  // Impossibly high
    t.criticalLevel = 99999.0; // Impossibly high
    thresholds.push_back(t);

    CHECK(engine.setThresholds(thresholds));

    engine.getMetrics();

    auto alerts = engine.getAlerts();
    CHECK(alerts.empty());
}

TEST_CASE("MonitorEngine - process list") {
    auto edrEngine = std::make_shared<ThreatOne::EDR::EDREngine>();
    MonitorEngine engine(edrEngine);
    engine.startMonitoring(MonitorType::Process);

    SUBCASE("getProcessList returns processes") {
        auto processes = engine.getProcessList();
        CHECK(!processes.empty());

        // Check that at least one process has a valid PID
        bool foundValid = false;
        for (const auto& proc : processes) {
            if (proc.pid > 0) {
                foundValid = true;
                break;
            }
        }
        CHECK(foundValid);
    }
}

TEST_CASE("MonitorEngine - file events") {
    auto edrEngine = std::make_shared<ThreatOne::EDR::EDREngine>();
    MonitorEngine engine(edrEngine);
    engine.startMonitoring(MonitorType::File);

    SUBCASE("getFileEvents does not crash") {
        auto events = engine.getFileEvents();
        CHECK(events.size() >= 0);
    }
}

TEST_CASE("MonitorEngine - default constructor works") {
    MonitorEngine engine;

    SUBCASE("Can start and get metrics") {
        engine.startMonitoring(MonitorType::Performance);
        auto metrics = engine.getMetrics();
        CHECK(metrics.memoryUsage > 0.0);
    }
}
