#include <doctest/doctest.h>
#include <siem/CorrelationEngine.h>
#include <siem/LogStorage.h>
#include <memory>
#include <string>

using namespace ThreatOne::SIEM;

TEST_CASE("CorrelationEngine - Add and retrieve rules") {
    auto storage = std::make_shared<LogStorage>();
    CorrelationEngine engine(storage);

    CorrelationRule rule;
    rule.name = "Brute force rule";
    rule.condition = "event_type=login_failed";
    rule.timeWindowSeconds = 600;
    rule.threshold = 3;
    rule.severity = "high";
    rule.enabled = true;

    std::string id = engine.addRule(rule);
    CHECK_FALSE(id.empty());

    auto rules = engine.getRules();
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].name == "Brute force rule");
}

TEST_CASE("CorrelationEngine - Triggers alert on threshold") {
    auto storage = std::make_shared<LogStorage>();
    CorrelationEngine engine(storage);

    CorrelationRule rule;
    rule.name = "Brute force";
    rule.condition = "event_type=login_failed";
    rule.timeWindowSeconds = 600;
    rule.threshold = 3;
    rule.severity = "high";
    rule.enabled = true;
    engine.addRule(rule);

    for (int i = 0; i < 5; i++) {
        LogEntry entry;
        entry.source = "auth";
        entry.message = "Login failed";
        entry.timestamp = "2024-01-15T10:0" + std::to_string(i) + ":00";
        entry.metadata["event_type"] = "login_failed";
        storage->store(entry);
    }

    auto alerts = engine.evaluate();
    REQUIRE_FALSE(alerts.empty());
    CHECK(alerts[0].severity == "high");
    CHECK(alerts[0].matchedLogIds.size() >= 3);
}

TEST_CASE("CorrelationEngine - Does not trigger below threshold") {
    auto storage = std::make_shared<LogStorage>();
    CorrelationEngine engine(storage);

    CorrelationRule rule;
    rule.name = "High threshold";
    rule.condition = "event_type=login_failed";
    rule.timeWindowSeconds = 600;
    rule.threshold = 10;
    rule.severity = "critical";
    rule.enabled = true;
    engine.addRule(rule);

    for (int i = 0; i < 3; i++) {
        LogEntry entry;
        entry.source = "auth";
        entry.message = "Failed login";
        entry.metadata["event_type"] = "login_failed";
        storage->store(entry);
    }

    auto alerts = engine.evaluate();
    CHECK(alerts.empty());
}

TEST_CASE("CorrelationEngine - Disabled rule does not fire") {
    auto storage = std::make_shared<LogStorage>();
    CorrelationEngine engine(storage);

    CorrelationRule rule;
    rule.name = "Disabled";
    rule.condition = "source=malware";
    rule.threshold = 1;
    rule.severity = "critical";
    rule.enabled = false;
    engine.addRule(rule);

    LogEntry entry;
    entry.source = "malware";
    entry.message = "Malware detected";
    storage->store(entry);

    auto alerts = engine.evaluate();
    CHECK(alerts.empty());
}

TEST_CASE("CorrelationEngine - Remove rule") {
    auto storage = std::make_shared<LogStorage>();
    CorrelationEngine engine(storage);

    CorrelationRule rule;
    rule.name = "ToRemove";
    rule.condition = "source=test";
    rule.threshold = 1;
    std::string id = engine.addRule(rule);

    CHECK(engine.removeRule(id));
    CHECK(engine.getRules().empty());
}
