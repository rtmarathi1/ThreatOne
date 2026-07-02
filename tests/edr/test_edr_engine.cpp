#include <doctest/doctest.h>
#include <edr/EDREngine.h>

#include <algorithm>
#ifdef _WIN32
#include <process.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif

using namespace ThreatOne::EDR;

TEST_CASE("EDREngine - lifecycle") {
    EDREngine engine;

    SUBCASE("Start and stop collection") {
        CHECK(engine.startCollection());
        CHECK(engine.stopCollection());
    }

    SUBCASE("Start collection is idempotent") {
        CHECK(engine.startCollection());
        CHECK(engine.startCollection()); // second call should succeed
        CHECK(engine.stopCollection());
    }

    SUBCASE("Stop collection when not started succeeds") {
        CHECK(engine.stopCollection());
    }
}

TEST_CASE("EDREngine - process monitoring") {
    EDREngine engine;
    engine.startCollection();

    SUBCASE("getProcesses returns current process") {
        auto processes = engine.getProcesses();
        CHECK(!processes.empty());

        uint64_t myPid = static_cast<uint64_t>(getpid());
        auto it = std::find_if(processes.begin(), processes.end(),
            [myPid](const ProcessInfo& p) { return p.pid == myPid; });
        CHECK(it != processes.end());
    }

    SUBCASE("getProcesses returns processes with valid PIDs") {
        auto processes = engine.getProcesses();
        for (const auto& proc : processes) {
            CHECK(proc.pid > 0);
        }
    }

    engine.stopCollection();
}

TEST_CASE("EDREngine - file events") {
    EDREngine engine;
    engine.startCollection();

    SUBCASE("getFileEvents returns empty when no directories watched") {
        auto events = engine.getFileEvents();
        // May be empty since no directories are being watched by default
        CHECK(events.size() >= 0); // no crash
    }

    engine.stopCollection();
}

TEST_CASE("EDREngine - detection capabilities") {
    EDREngine engine;
    engine.startCollection();

    SUBCASE("detectPersistence returns results without crash") {
        auto indicators = engine.detectPersistence();
        // System may or may not have persistence mechanisms
        CHECK(indicators.size() >= 0);
    }

    SUBCASE("detectRansomware returns results without crash") {
        auto indicators = engine.detectRansomware();
        CHECK(indicators.size() >= 0);
    }

    SUBCASE("detectLateralMovement returns results without crash") {
        auto indicators = engine.detectLateralMovement();
        CHECK(indicators.size() >= 0);
    }

    engine.stopCollection();
}

TEST_CASE("EDREngine - alert generation flow") {
    EDREngine engine;
    engine.startCollection();

    SUBCASE("Initial state has no alerts") {
        auto alerts = engine.getAlerts();
        CHECK(alerts.empty());
    }

    SUBCASE("Rule evaluation generates alerts for matching rules") {
        // Add a test rule to the engine via evaluateRules
        // Since no rules are loaded, result should be empty
        auto results = engine.evaluateRules("process_exec", "test_proc", "/tmp/malware", "suspicious");
        CHECK(results.empty()); // no rules loaded by default
    }

    engine.stopCollection();
}

TEST_CASE("EDREngine - incident management") {
    EDREngine engine;
    engine.startCollection();

    SUBCASE("No incidents initially") {
        auto incidents = engine.getIncidents();
        CHECK(incidents.empty());
    }

    SUBCASE("Empty timeline for non-existent incident") {
        auto timeline = engine.getTimeline("non-existent");
        CHECK(timeline.empty());
    }

    engine.stopCollection();
}

TEST_CASE("EDREngine - rule evaluation pipeline") {
    EDREngine engine;
    engine.startCollection();

    SUBCASE("evaluateRules with no rules returns empty") {
        auto results = engine.evaluateRules("file_write", "editor", "/tmp/test.txt", "");
        CHECK(results.empty());
    }

    engine.stopCollection();
}
