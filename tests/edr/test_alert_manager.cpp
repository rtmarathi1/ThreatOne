#include <doctest/doctest.h>
#include <edr/AlertManager.h>
#include <core/EventBus.h>

#include <thread>
#include <chrono>
#include <string>

using namespace ThreatOne::EDR;
using namespace ThreatOne::Core;

TEST_CASE("AlertManager - generate alert returns valid ID") {
    AlertManager manager;
    auto id = manager.generateAlert("ProcessMonitor", "high",
                                     "Suspicious process detected", "pid=1234");
    CHECK(!id.empty());
    CHECK(id.find("ALERT-") == 0);
}

TEST_CASE("AlertManager - generated alert has correct fields") {
    AlertManager manager;
    manager.generateAlert("FileMonitor", "critical",
                          "Ransomware file encryption detected",
                          "path=/home/user/docs");

    auto alerts = manager.getAlerts();
    REQUIRE(alerts.size() == 1);
    CHECK(alerts[0].source == "FileMonitor");
    CHECK(alerts[0].severity == "critical");
    CHECK(alerts[0].description == "Ransomware file encryption detected");
    CHECK(alerts[0].evidence == "path=/home/user/docs");
    CHECK(alerts[0].status == AlertStatus::New);
}

TEST_CASE("AlertManager - alerts sorted by severity") {
    AlertManager manager;
    manager.setDeduplicationWindow(std::chrono::seconds(0)); // Disable dedup for this test
    manager.generateAlert("src1", "low", "Low alert", "");
    manager.generateAlert("src2", "critical", "Critical alert", "");
    manager.generateAlert("src3", "medium", "Medium alert", "");

    auto alerts = manager.getAlerts();
    REQUIRE(alerts.size() == 3);
    CHECK(alerts[0].severity == "critical");
    CHECK(alerts[1].severity == "medium");
    CHECK(alerts[2].severity == "low");
}

TEST_CASE("AlertManager - deduplication within window") {
    AlertManager manager;
    manager.setDeduplicationWindow(std::chrono::seconds(10));

    auto id1 = manager.generateAlert("Monitor", "high", "Same alert", "ev1");
    auto id2 = manager.generateAlert("Monitor", "high", "Same alert", "ev2");

    CHECK(!id1.empty());
    CHECK(id2.empty()); // Deduplicated

    auto stats = manager.getAlertStats();
    CHECK(stats.totalAlerts == 1);
    CHECK(stats.deduplicated == 1);
}

TEST_CASE("AlertManager - different alerts not deduplicated") {
    AlertManager manager;
    manager.setDeduplicationWindow(std::chrono::seconds(10));

    manager.generateAlert("Monitor", "high", "Alert 1", "");
    manager.generateAlert("Monitor", "high", "Alert 2", "");

    auto stats = manager.getAlertStats();
    CHECK(stats.totalAlerts == 2);
    CHECK(stats.deduplicated == 0);
}

TEST_CASE("AlertManager - different sources not deduplicated") {
    AlertManager manager;
    manager.setDeduplicationWindow(std::chrono::seconds(10));

    manager.generateAlert("Source1", "high", "Same description", "");
    manager.generateAlert("Source2", "high", "Same description", "");

    auto stats = manager.getAlertStats();
    CHECK(stats.totalAlerts == 2);
}

TEST_CASE("AlertManager - acknowledge existing alert") {
    AlertManager manager;
    auto id = manager.generateAlert("Monitor", "high", "Test alert", "evidence");
    CHECK(manager.acknowledgeAlert(id));

    auto alerts = manager.getAlerts();
    REQUIRE(alerts.size() == 1);
    CHECK(alerts[0].status == AlertStatus::Acknowledged);
}

TEST_CASE("AlertManager - acknowledge non-existing alert") {
    AlertManager manager;
    CHECK_FALSE(manager.acknowledgeAlert("ALERT-9999"));
}

TEST_CASE("AlertManager - resolve alert") {
    AlertManager manager;
    auto id = manager.generateAlert("Monitor", "medium", "Alert", "");
    CHECK(manager.resolveAlert(id));

    auto alerts = manager.getAlerts();
    REQUIRE(alerts.size() == 1);
    CHECK(alerts[0].status == AlertStatus::Resolved);
}

TEST_CASE("AlertManager - filter by source") {
    AlertManager manager;
    manager.setDeduplicationWindow(std::chrono::seconds(0));
    manager.generateAlert("ProcessMonitor", "high", "Process alert", "");
    manager.generateAlert("FileMonitor", "critical", "File alert", "");
    manager.generateAlert("NetworkMonitor", "low", "Network alert", "");

    AlertFilter filter;
    filter.filterBySource = true;
    filter.source = "FileMonitor";

    auto alerts = manager.getAlerts(filter);
    REQUIRE(alerts.size() == 1);
    CHECK(alerts[0].source == "FileMonitor");
}

TEST_CASE("AlertManager - filter by severity") {
    AlertManager manager;
    manager.setDeduplicationWindow(std::chrono::seconds(0));
    manager.generateAlert("src1", "high", "High alert", "");
    manager.generateAlert("src2", "critical", "Critical alert", "");
    manager.generateAlert("src3", "low", "Low alert", "");

    AlertFilter filter;
    filter.filterBySeverity = true;
    filter.severity = "high";

    auto alerts = manager.getAlerts(filter);
    REQUIRE(alerts.size() == 1);
    CHECK(alerts[0].severity == "high");
}

TEST_CASE("AlertManager - filter by status") {
    AlertManager manager;
    manager.setDeduplicationWindow(std::chrono::seconds(0));
    manager.generateAlert("src1", "high", "Alert 1", "");
    manager.generateAlert("src2", "medium", "Alert 2", "");
    auto id3 = manager.generateAlert("src3", "low", "Alert 3", "");
    manager.acknowledgeAlert(id3);

    AlertFilter filter;
    filter.filterByStatus = true;
    filter.status = AlertStatus::Acknowledged;

    auto alerts = manager.getAlerts(filter);
    REQUIRE(alerts.size() == 1);
    CHECK(alerts[0].source == "src3");
}

TEST_CASE("AlertManager - EventBus integration") {
    AlertManager manager;

    bool eventReceived = false;
    std::string eventDescription;

    auto subId = EventBus::instance().subscribe<SecurityEvent>(
        [&](const SecurityEvent& event) {
            eventReceived = true;
            eventDescription = event.description();
        });

    manager.generateAlert("TestSource", "high", "Test security event", "test_evidence");

    CHECK(eventReceived);
    CHECK(eventDescription == "Test security event");

    EventBus::instance().unsubscribe(subId);
}

TEST_CASE("AlertManager - statistics") {
    AlertManager manager;
    manager.setDeduplicationWindow(std::chrono::seconds(0));
    manager.generateAlert("src", "high", "Alert 1", "");
    auto id2 = manager.generateAlert("src2", "medium", "Alert 2", "");
    manager.acknowledgeAlert(id2);
    auto id3 = manager.generateAlert("src3", "low", "Alert 3", "");
    manager.resolveAlert(id3);

    auto stats = manager.getAlertStats();
    CHECK(stats.totalAlerts == 3);
    CHECK(stats.newAlerts == 1);
    CHECK(stats.acknowledgedAlerts == 1);
    CHECK(stats.resolvedAlerts == 1);
}
