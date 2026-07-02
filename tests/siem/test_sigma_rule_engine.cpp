#include <doctest/doctest.h>
#include <siem/SigmaRuleEngine.h>
#include <string>
#include <vector>

using namespace ThreatOne::SIEM;

TEST_CASE("SigmaRuleEngine - Add and retrieve rules") {
    SigmaRuleEngine engine;

    SigmaRule rule;
    rule.title = "Failed Login Detection";
    rule.severity = "high";
    rule.enabled = true;

    SigmaDetection det;
    det.name = "selection";
    SigmaFieldMatch fm;
    fm.field = "event_type";
    fm.values = {"login_failed"};
    det.fieldMatches.push_back(fm);
    rule.detections.push_back(det);
    rule.condition = "selection";

    std::string id = engine.addRule(rule);
    CHECK_FALSE(id.empty());

    auto rules = engine.getRules();
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].title == "Failed Login Detection");
}

TEST_CASE("SigmaRuleEngine - Remove rule") {
    SigmaRuleEngine engine;

    SigmaRule rule;
    rule.title = "Test";
    rule.enabled = true;
    std::string id = engine.addRule(rule);

    CHECK(engine.removeRule(id));
    CHECK(engine.getRules().empty());
}

TEST_CASE("SigmaRuleEngine - Evaluate simple rule") {
    SigmaRuleEngine engine;

    SigmaRule rule;
    rule.title = "Detect login failure";
    rule.severity = "medium";
    rule.enabled = true;

    SigmaDetection det;
    det.name = "selection";
    SigmaFieldMatch fm;
    fm.field = "event_type";
    fm.values = {"login_failed"};
    det.fieldMatches.push_back(fm);
    rule.detections.push_back(det);
    rule.condition = "selection";

    engine.addRule(rule);

    LogEntry entry;
    entry.source = "auth";
    entry.message = "Login attempt";
    entry.metadata["event_type"] = "login_failed";

    auto matches = engine.evaluate(entry);
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].severity == "medium");
}
