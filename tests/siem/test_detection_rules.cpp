#include <doctest/doctest.h>
#include <siem/DetectionRules.h>
#include <string>
#include <vector>

using namespace ThreatOne::SIEM;

TEST_CASE("DetectionRules - Add and retrieve rules") {
    DetectionRules rules;

    SIEMRule rule;
    rule.name = "Login failure detection";
    rule.condition = "event_type=login_failed";
    rule.severity = "high";
    rule.enabled = true;

    std::string id = rules.addRule(rule);
    CHECK_FALSE(id.empty());

    auto allRules = rules.getRules();
    REQUIRE(allRules.size() == 1);
    CHECK(allRules[0].name == "Login failure detection");
}

TEST_CASE("DetectionRules - Remove rule") {
    DetectionRules rules;

    SIEMRule rule;
    rule.name = "Test rule";
    rule.condition = "source=firewall";
    std::string id = rules.addRule(rule);

    CHECK(rules.removeRule(id));
    CHECK(rules.getRules().empty());
}

TEST_CASE("DetectionRules - Enable and disable rules") {
    DetectionRules rules;

    SIEMRule rule;
    rule.name = "Toggle rule";
    rule.condition = "source=auth";
    rule.enabled = true;
    std::string id = rules.addRule(rule);

    CHECK(rules.disableRule(id));
    auto r = rules.getRule(id);
    CHECK_FALSE(r.enabled);

    CHECK(rules.enableRule(id));
    r = rules.getRule(id);
    CHECK(r.enabled);
}

TEST_CASE("DetectionRules - Evaluate against log entry") {
    DetectionRules rules;

    SIEMRule rule1;
    rule1.name = "Firewall rule";
    rule1.condition = "source=firewall";
    rule1.enabled = true;
    rules.addRule(rule1);

    SIEMRule rule2;
    rule2.name = "Auth rule";
    rule2.condition = "event_type=login_failed";
    rule2.enabled = true;
    rules.addRule(rule2);

    LogEntry entry;
    entry.source = "firewall";
    entry.message = "Blocked connection";

    auto matches = rules.evaluate(entry);
    REQUIRE(matches.size() == 1);

    // Test with metadata match
    LogEntry authEntry;
    authEntry.source = "auth";
    authEntry.message = "Login attempt";
    authEntry.metadata["event_type"] = "login_failed";

    auto authMatches = rules.evaluate(authEntry);
    REQUIRE(authMatches.size() == 1);
}

TEST_CASE("DetectionRules - Disabled rule does not match") {
    DetectionRules rules;

    SIEMRule rule;
    rule.name = "Disabled rule";
    rule.condition = "source=firewall";
    rule.enabled = false;
    rules.addRule(rule);

    LogEntry entry;
    entry.source = "firewall";
    entry.message = "test";

    auto matches = rules.evaluate(entry);
    CHECK(matches.empty());
}

TEST_CASE("DetectionRules - Substring match in message") {
    DetectionRules rules;

    SIEMRule rule;
    rule.name = "Malware keyword";
    rule.condition = "malware detected";
    rule.enabled = true;
    rules.addRule(rule);

    LogEntry entry;
    entry.source = "scanner";
    entry.message = "Alert: malware detected in file.exe";

    auto matches = rules.evaluate(entry);
    CHECK(matches.size() == 1);
}
