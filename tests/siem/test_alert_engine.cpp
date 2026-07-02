#include <doctest/doctest.h>
#include <siem/AlertEngine.h>
#include <string>
#include <vector>

using namespace ThreatOne::SIEM;

TEST_CASE("AlertEngine - Create and retrieve alert") {
    AlertEngine engine;

    SIEMAlert alert;
    alert.title = "Brute force detected";
    alert.severity = "high";
    alert.description = "Multiple login failures";
    alert.ruleId = "RULE-1";

    std::string id = engine.createAlert(alert);
    CHECK_FALSE(id.empty());

    auto alerts = engine.getAlerts();
    REQUIRE(alerts.size() == 1);
    CHECK(alerts[0].title == "Brute force detected");
}

TEST_CASE("AlertEngine - Get alert by ID") {
    AlertEngine engine;

    SIEMAlert alert;
    alert.title = "Test Alert";
    alert.severity = "medium";
    std::string id = engine.createAlert(alert);

    auto retrieved = engine.getAlert(id);
    CHECK(retrieved.title == "Test Alert");
}

TEST_CASE("AlertEngine - Get alerts by severity") {
    AlertEngine engine;

    SIEMAlert high;
    high.title = "High Alert";
    high.severity = "high";
    engine.createAlert(high);

    SIEMAlert low;
    low.title = "Low Alert";
    low.severity = "low";
    engine.createAlert(low);

    auto highAlerts = engine.getAlertsBySeverity("high");
    REQUIRE(highAlerts.size() == 1);
    CHECK(highAlerts[0].title == "High Alert");
}

TEST_CASE("AlertEngine - Get alerts by rule") {
    AlertEngine engine;

    SIEMAlert a1;
    a1.title = "Alert 1";
    a1.ruleId = "RULE-1";
    engine.createAlert(a1);

    SIEMAlert a2;
    a2.title = "Alert 2";
    a2.ruleId = "RULE-2";
    engine.createAlert(a2);

    auto ruleAlerts = engine.getAlertsByRule("RULE-1");
    REQUIRE(ruleAlerts.size() == 1);
    CHECK(ruleAlerts[0].title == "Alert 1");
}

TEST_CASE("AlertEngine - Acknowledge alert") {
    AlertEngine engine;

    SIEMAlert alert;
    alert.title = "To Acknowledge";
    std::string id = engine.createAlert(alert);

    CHECK(engine.acknowledgeAlert(id));
}

TEST_CASE("AlertEngine - Resolve alert") {
    AlertEngine engine;

    SIEMAlert alert;
    alert.title = "To Resolve";
    std::string id = engine.createAlert(alert);

    CHECK(engine.resolveAlert(id));
    CHECK(engine.getActiveAlertCount() == 0);
}

TEST_CASE("AlertEngine - Dismiss alert") {
    AlertEngine engine;

    SIEMAlert alert;
    alert.title = "To Dismiss";
    std::string id = engine.createAlert(alert);

    CHECK(engine.dismissAlert(id));
    CHECK(engine.getAlertCount() == 0);
}

TEST_CASE("AlertEngine - Deduplication check") {
    AlertEngine engine;

    SIEMAlert alert;
    alert.title = "Duplicate Alert";
    alert.severity = "high";
    alert.ruleId = "RULE-1";
    engine.createAlert(alert);

    CHECK(engine.isDuplicate(alert));

    SIEMAlert different;
    different.title = "Different Alert";
    different.severity = "low";
    different.ruleId = "RULE-2";
    CHECK_FALSE(engine.isDuplicate(different));
}
