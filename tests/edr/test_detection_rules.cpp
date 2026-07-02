#include <doctest/doctest.h>
#include <edr/DetectionRulesEngine.h>
#include <string>

using namespace ThreatOne::EDR;

TEST_CASE("DetectionRulesEngine - load single rule from JSON") {
    DetectionRulesEngine engine;
    std::string json = R"({
        "id": "RULE-001",
        "name": "Suspicious Process",
        "description": "Detects suspicious process execution",
        "severity": "high",
        "logic": "AND",
        "conditions": [
            {"field": "type", "operator": "equals", "value": "process_exec"},
            {"field": "source", "operator": "contains", "value": "malware"}
        ],
        "actions": ["alert", "log"]
    })";

    CHECK(engine.loadRules(json));
    CHECK(engine.getRuleCount() == 1);
}

TEST_CASE("DetectionRulesEngine - load multiple rules from JSON array") {
    DetectionRulesEngine engine;
    std::string json = R"([
        {
            "id": "RULE-001",
            "name": "Rule 1",
            "severity": "low",
            "logic": "AND",
            "conditions": [{"field": "type", "operator": "equals", "value": "file_write"}],
            "actions": ["log"]
        },
        {
            "id": "RULE-002",
            "name": "Rule 2",
            "severity": "high",
            "logic": "OR",
            "conditions": [{"field": "type", "operator": "equals", "value": "network_out"}],
            "actions": ["alert"]
        }
    ])";

    CHECK(engine.loadRules(json));
    CHECK(engine.getRuleCount() == 2);
}

TEST_CASE("DetectionRulesEngine - invalid JSON returns false") {
    DetectionRulesEngine engine;
    CHECK_FALSE(engine.loadRules("not valid json{{{"));
    CHECK(engine.getRuleCount() == 0);
}

TEST_CASE("DetectionRulesEngine - add rule programmatically") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "RULE-100";
    rule.name = "Test Rule";
    rule.severity = "medium";
    rule.logic = "AND";
    rule.conditions.push_back({"type", "equals", "test"});
    rule.actions = {"alert"};

    engine.addRule(rule);
    CHECK(engine.getRuleCount() == 1);
}

TEST_CASE("DetectionRulesEngine - equals operator matches") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "R1";
    rule.name = "Match Type";
    rule.severity = "high";
    rule.logic = "AND";
    rule.conditions.push_back({"type", "equals", "file_write"});
    rule.actions = {"alert"};
    engine.addRule(rule);

    EDREvent event;
    event.type = "file_write";
    event.source = "test_process";

    auto matches = engine.evaluate(event);
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].ruleId == "R1");
    CHECK(matches[0].severity == "high");
}

TEST_CASE("DetectionRulesEngine - non-matching event") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "R1";
    rule.name = "Match Type";
    rule.severity = "high";
    rule.logic = "AND";
    rule.conditions.push_back({"type", "equals", "file_delete"});
    rule.actions = {"alert"};
    engine.addRule(rule);

    EDREvent event;
    event.type = "file_write";

    auto matches = engine.evaluate(event);
    CHECK(matches.empty());
}

TEST_CASE("DetectionRulesEngine - AND logic requires all conditions") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "R1";
    rule.name = "Multi-condition";
    rule.severity = "critical";
    rule.logic = "AND";
    rule.conditions.push_back({"type", "equals", "file_write"});
    rule.conditions.push_back({"source", "contains", "malware"});
    rule.actions = {"alert", "block"};
    engine.addRule(rule);

    EDREvent event1;
    event1.type = "file_write";
    event1.source = "malware.exe";

    auto matches1 = engine.evaluate(event1);
    CHECK(matches1.size() == 1);

    EDREvent event2;
    event2.type = "file_write";
    event2.source = "notepad.exe";

    auto matches2 = engine.evaluate(event2);
    CHECK(matches2.empty());
}

TEST_CASE("DetectionRulesEngine - OR logic requires any condition") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "R1";
    rule.name = "OR condition";
    rule.severity = "medium";
    rule.logic = "OR";
    rule.conditions.push_back({"type", "equals", "file_delete"});
    rule.conditions.push_back({"source", "contains", "suspicious"});
    rule.actions = {"log"};
    engine.addRule(rule);

    EDREvent event;
    event.type = "file_write";
    event.source = "suspicious_proc";

    auto matches = engine.evaluate(event);
    CHECK(matches.size() == 1);
}

TEST_CASE("DetectionRulesEngine - contains operator") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "R1";
    rule.name = "Contains";
    rule.severity = "low";
    rule.logic = "AND";
    rule.conditions.push_back({"path", "contains", "/tmp/"});
    rule.actions = {"log"};
    engine.addRule(rule);

    EDREvent event;
    event.type = "file_write";
    event.path = "/tmp/malicious_script.sh";

    auto matches = engine.evaluate(event);
    CHECK(matches.size() == 1);
}

TEST_CASE("DetectionRulesEngine - regex operator") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "R1";
    rule.name = "Regex Match";
    rule.severity = "high";
    rule.logic = "AND";
    rule.conditions.push_back({"path", "regex", ".*\\.(exe|bat|cmd)$"});
    rule.actions = {"alert"};
    engine.addRule(rule);

    EDREvent event;
    event.type = "file_create";
    event.path = "/tmp/payload.exe";

    auto matches = engine.evaluate(event);
    CHECK(matches.size() == 1);
}

TEST_CASE("DetectionRulesEngine - greater_than operator") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "R1";
    rule.name = "High Entropy";
    rule.severity = "high";
    rule.logic = "AND";
    rule.conditions.push_back({"entropy", "greater_than", "7.5"});
    rule.actions = {"alert"};
    engine.addRule(rule);

    EDREvent event;
    event.type = "file_write";
    event.entropy = 7.8;

    auto matches = engine.evaluate(event);
    CHECK(matches.size() == 1);
}

TEST_CASE("DetectionRulesEngine - less_than operator") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "R1";
    rule.name = "Small File";
    rule.severity = "info";
    rule.logic = "AND";
    rule.conditions.push_back({"dataSize", "less_than", "100"});
    rule.actions = {"log"};
    engine.addRule(rule);

    EDREvent event;
    event.type = "file_write";
    event.dataSize = 50;

    auto matches = engine.evaluate(event);
    CHECK(matches.size() == 1);
}

TEST_CASE("DetectionRulesEngine - in_list operator") {
    DetectionRulesEngine engine;
    DetectionRule rule;
    rule.id = "R1";
    rule.name = "Known Type";
    rule.severity = "medium";
    rule.logic = "AND";
    rule.conditions.push_back({"type", "in_list", "file_write, file_delete, file_rename"});
    rule.actions = {"log"};
    engine.addRule(rule);

    EDREvent event;
    event.type = "file_delete";

    auto matches = engine.evaluate(event);
    CHECK(matches.size() == 1);

    EDREvent event2;
    event2.type = "process_exec";

    auto matches2 = engine.evaluate(event2);
    CHECK(matches2.empty());
}

TEST_CASE("DetectionRulesEngine - rule management") {
    DetectionRulesEngine engine;

    DetectionRule rule1;
    rule1.id = "R1";
    rule1.name = "Rule 1";
    rule1.severity = "low";
    rule1.logic = "AND";
    rule1.conditions.push_back({"type", "equals", "test"});
    engine.addRule(rule1);

    DetectionRule rule2;
    rule2.id = "R2";
    rule2.name = "Rule 2";
    rule2.severity = "high";
    rule2.logic = "AND";
    rule2.conditions.push_back({"type", "equals", "test2"});
    engine.addRule(rule2);

    CHECK(engine.getRuleCount() == 2);

    engine.removeRule("R1");
    CHECK(engine.getRuleCount() == 1);
    auto rules = engine.getRules();
    CHECK(rules[0].id == "R2");

    engine.clearRules();
    CHECK(engine.getRuleCount() == 0);
}
