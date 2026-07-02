#include <doctest/doctest.h>
#include <fleet/PolicyEngine.h>
#include <string>

using namespace ThreatOne::Fleet;

TEST_CASE("PolicyEngine - Create policy") {
    PolicyEngine engine;
    SecurityPolicy policy;
    policy.name = "Baseline Security";
    policy.priority = 10;

    PolicyRule rule;
    rule.id = "r1";
    rule.type = PolicyRuleType::AntivirusEnabled;
    rule.action = PolicyAction::Enforce;
    rule.severity = PolicySeverity::High;
    policy.rules.push_back(rule);

    std::string id = engine.createPolicy(policy);
    CHECK_FALSE(id.empty());

    auto retrieved = engine.getPolicy(id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Baseline Security");
    CHECK(retrieved->version == 1);
    CHECK(retrieved->rules.size() == 1);
}

TEST_CASE("PolicyEngine - Update policy increments version") {
    PolicyEngine engine;
    SecurityPolicy policy;
    policy.name = "Original";
    std::string id = engine.createPolicy(policy);

    SecurityPolicy updated;
    updated.name = "Updated";
    CHECK(engine.updatePolicy(id, updated));

    auto retrieved = engine.getPolicy(id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Updated");
    CHECK(retrieved->version == 2);
}

TEST_CASE("PolicyEngine - Update nonexistent policy returns false") {
    PolicyEngine engine;
    SecurityPolicy updated;
    updated.name = "NoSuchPolicy";
    CHECK_FALSE(engine.updatePolicy("invalid-id", updated));
}

TEST_CASE("PolicyEngine - Delete policy") {
    PolicyEngine engine;
    SecurityPolicy policy;
    policy.name = "ToDelete";
    std::string id = engine.createPolicy(policy);

    CHECK(engine.deletePolicy(id));
    CHECK_FALSE(engine.getPolicy(id).has_value());
}

TEST_CASE("PolicyEngine - Delete nonexistent policy returns false") {
    PolicyEngine engine;
    CHECK_FALSE(engine.deletePolicy("no-such-policy"));
}

TEST_CASE("PolicyEngine - Get all policies") {
    PolicyEngine engine;
    SecurityPolicy p1;
    p1.name = "Policy1";
    SecurityPolicy p2;
    p2.name = "Policy2";

    engine.createPolicy(p1);
    engine.createPolicy(p2);

    auto all = engine.getPolicies();
    CHECK(all.size() == 2);
}

TEST_CASE("PolicyEngine - Policy version history") {
    PolicyEngine engine;
    SecurityPolicy policy;
    policy.name = "Versioned";
    std::string id = engine.createPolicy(policy);

    SecurityPolicy v2;
    v2.name = "Versioned-v2";
    engine.updatePolicy(id, v2);

    SecurityPolicy v3;
    v3.name = "Versioned-v3";
    engine.updatePolicy(id, v3);

    auto history = engine.getPolicyHistory(id);
    CHECK(history.size() == 3);
    CHECK(history[0].version == 1);
    CHECK(history[1].version == 2);
    CHECK(history[2].version == 3);
}

TEST_CASE("PolicyEngine - Distribute policy to groups") {
    PolicyEngine engine;
    SecurityPolicy policy;
    policy.name = "Distributed";
    std::string id = engine.createPolicy(policy);

    CHECK(engine.distributePolicy(id, {"group-1", "group-2"}));

    auto retrieved = engine.getPolicy(id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->targetGroups.size() == 2);
}

TEST_CASE("PolicyEngine - Distribute nonexistent policy returns false") {
    PolicyEngine engine;
    CHECK_FALSE(engine.distributePolicy("no-policy", {"group-1"}));
}

TEST_CASE("PolicyEngine - Check compliance defaults to compliant") {
    PolicyEngine engine;
    SecurityPolicy policy;
    policy.name = "ComplianceTest";
    std::string policyId = engine.createPolicy(policy);

    auto compliance = engine.checkCompliance("endpoint-1", policyId);
    CHECK(compliance.compliant == true);
    CHECK(compliance.violations.empty());
}

TEST_CASE("PolicyEngine - Set and check non-compliant endpoint") {
    PolicyEngine engine;
    SecurityPolicy policy;
    policy.name = "StrictPolicy";
    std::string policyId = engine.createPolicy(policy);

    PolicyViolation violation;
    violation.ruleId = "r1";
    violation.ruleType = PolicyRuleType::FirewallEnabled;
    violation.detail = "Firewall disabled";
    violation.severity = PolicySeverity::Critical;

    engine.setEndpointCompliance("endpoint-1", policyId, false, {violation});

    auto compliance = engine.checkCompliance("endpoint-1", policyId);
    CHECK(compliance.compliant == false);
    CHECK(compliance.violations.size() == 1);
    CHECK(compliance.violations[0].detail == "Firewall disabled");
}

TEST_CASE("PolicyEngine - Get compliance status for endpoint") {
    PolicyEngine engine;
    SecurityPolicy p1;
    p1.name = "P1";
    std::string id1 = engine.createPolicy(p1);

    SecurityPolicy p2;
    p2.name = "P2";
    std::string id2 = engine.createPolicy(p2);

    engine.setEndpointCompliance("ep-1", id1, true);
    engine.setEndpointCompliance("ep-1", id2, false);

    auto statuses = engine.getComplianceStatus("ep-1");
    CHECK(statuses.size() == 2);
}

TEST_CASE("PolicyEngine - Inherited policies global and group") {
    PolicyEngine engine;

    // Create a global policy
    SecurityPolicy globalPolicy;
    globalPolicy.name = "GlobalPolicy";
    globalPolicy.isGlobal = true;
    globalPolicy.priority = 100;
    engine.createPolicy(globalPolicy);

    // Create a group-level policy
    SecurityPolicy groupPolicy;
    groupPolicy.name = "GroupPolicy";
    groupPolicy.targetGroups = {"group-A"};
    groupPolicy.priority = 50;
    engine.createPolicy(groupPolicy);

    // Create another policy for a different group
    SecurityPolicy otherPolicy;
    otherPolicy.name = "OtherGroupPolicy";
    otherPolicy.targetGroups = {"group-B"};
    otherPolicy.priority = 30;
    engine.createPolicy(otherPolicy);

    auto inherited = engine.getInheritedPolicies("ep-1", "group-A");
    // Should include global + group-A policy, but not group-B
    CHECK(inherited.size() == 2);
    // Sorted by priority descending
    CHECK(inherited[0].name == "GlobalPolicy");
    CHECK(inherited[1].name == "GroupPolicy");
}

TEST_CASE("PolicyEngine - Inherited policies without group only gets global") {
    PolicyEngine engine;

    SecurityPolicy globalPolicy;
    globalPolicy.name = "Global";
    globalPolicy.isGlobal = true;
    engine.createPolicy(globalPolicy);

    SecurityPolicy groupPolicy;
    groupPolicy.name = "GroupOnly";
    groupPolicy.targetGroups = {"some-group"};
    engine.createPolicy(groupPolicy);

    auto inherited = engine.getInheritedPolicies("ep-1", "");
    CHECK(inherited.size() == 1);
    CHECK(inherited[0].name == "Global");
}

TEST_CASE("PolicyEngine - Policy history for nonexistent policy is empty") {
    PolicyEngine engine;
    auto history = engine.getPolicyHistory("nonexistent");
    CHECK(history.empty());
}
