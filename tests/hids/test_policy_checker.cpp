#include <doctest/doctest.h>
#include <hids/PolicyChecker.h>

using namespace ThreatOne::HIDS;

TEST_CASE("PolicyChecker - Add and get policies") {
    PolicyChecker checker;

    SecurityPolicy policy;
    policy.name = "Shadow File Permissions";
    policy.category = PolicyCategory::FilePermission;
    policy.expectedValue = "0600";
    policy.path = "/etc/shadow";
    policy.severity = "critical";

    auto id = checker.addPolicy(policy);
    CHECK_FALSE(id.empty());

    auto policies = checker.getPolicies();
    CHECK(policies.size() == 1);
    CHECK(policies[0].name == "Shadow File Permissions");
}

TEST_CASE("PolicyChecker - Add policy with empty name fails") {
    PolicyChecker checker;
    SecurityPolicy policy;
    policy.name = "";
    CHECK(checker.addPolicy(policy).empty());
}

TEST_CASE("PolicyChecker - Remove policy") {
    PolicyChecker checker;
    SecurityPolicy policy;
    policy.name = "Test";
    auto id = checker.addPolicy(policy);

    CHECK(checker.removePolicy(id));
    CHECK_FALSE(checker.removePolicy("nonexistent"));
    CHECK(checker.getPolicies().empty());
}

TEST_CASE("PolicyChecker - Enable and disable policies") {
    PolicyChecker checker;
    SecurityPolicy policy;
    policy.name = "Test";
    policy.enabled = true;
    auto id = checker.addPolicy(policy);

    CHECK(checker.disablePolicy(id));
    auto p = checker.getPolicy(id);
    CHECK_FALSE(p.enabled);

    CHECK(checker.enablePolicy(id));
    p = checker.getPolicy(id);
    CHECK(p.enabled);
}

TEST_CASE("PolicyChecker - Run all checks") {
    PolicyChecker checker;

    SecurityPolicy policy1;
    policy1.name = "File Permission Check";
    policy1.category = PolicyCategory::FilePermission;
    policy1.expectedValue = "0644";
    policy1.path = "/etc/passwd";
    policy1.severity = "medium";
    checker.addPolicy(policy1);

    SecurityPolicy policy2;
    policy2.name = "Service Check";
    policy2.category = PolicyCategory::ServiceConfig;
    policy2.expectedValue = "enabled";
    policy2.severity = "low";
    checker.addPolicy(policy2);

    auto results = checker.runAllChecks();
    CHECK(results.size() == 2);

    for (const auto& result : results) {
        CHECK_FALSE(result.policyId.empty());
        CHECK_FALSE(result.checkedAt.empty());
    }
}

TEST_CASE("PolicyChecker - Compliance policy evaluates correctly") {
    PolicyChecker checker;

    SecurityPolicy policy;
    policy.name = "Correct Permission";
    policy.category = PolicyCategory::FilePermission;
    policy.expectedValue = "0644";  // Matches the simulated value
    policy.path = "/etc/config";
    policy.severity = "medium";
    checker.addPolicy(policy);

    auto results = checker.runAllChecks();
    REQUIRE(results.size() == 1);
    CHECK(results[0].compliant);
}

TEST_CASE("PolicyChecker - Non-compliant generates violation") {
    PolicyChecker checker;

    SecurityPolicy policy;
    policy.name = "Strict Permission";
    policy.category = PolicyCategory::FilePermission;
    policy.expectedValue = "0600";  // Does not match "0644"
    policy.path = "/etc/shadow";
    policy.severity = "critical";
    checker.addPolicy(policy);

    checker.runAllChecks();

    auto violations = checker.getViolations();
    CHECK(violations.size() == 1);
    CHECK(violations[0].policyName == "Strict Permission");
    CHECK(violations[0].severity == "critical");
}

TEST_CASE("PolicyChecker - Disabled policies are skipped") {
    PolicyChecker checker;

    SecurityPolicy policy;
    policy.name = "Disabled";
    policy.expectedValue = "something";
    policy.enabled = false;
    checker.addPolicy(policy);

    auto results = checker.runAllChecks();
    CHECK(results.empty());
}

TEST_CASE("PolicyChecker - Compliance summary") {
    PolicyChecker checker;

    SecurityPolicy compliant;
    compliant.name = "Compliant";
    compliant.category = PolicyCategory::FilePermission;
    compliant.expectedValue = "0644";
    checker.addPolicy(compliant);

    SecurityPolicy nonCompliant;
    nonCompliant.name = "NonCompliant";
    nonCompliant.category = PolicyCategory::FilePermission;
    nonCompliant.expectedValue = "0600";
    nonCompliant.severity = "high";
    checker.addPolicy(nonCompliant);

    checker.runAllChecks();

    auto summary = checker.getComplianceSummary();
    CHECK(summary.totalPolicies == 2);
    CHECK(summary.compliant == 1);
    CHECK(summary.nonCompliant == 1);
    CHECK(summary.compliancePercent == doctest::Approx(50.0));
}

TEST_CASE("PolicyChecker - Clear violations") {
    PolicyChecker checker;

    PolicyViolation v;
    v.id = "V-1";
    v.policyName = "Test";
    checker.addViolation(v);

    CHECK(checker.getViolations().size() == 1);
    checker.clearViolations();
    CHECK(checker.getViolations().empty());
}

TEST_CASE("PolicyChecker - Total checks counter") {
    PolicyChecker checker;

    SecurityPolicy policy;
    policy.name = "Test";
    policy.category = PolicyCategory::ServiceConfig;
    policy.expectedValue = "enabled";
    auto id = checker.addPolicy(policy);

    checker.checkPolicy(id);
    checker.checkPolicy(id);
    CHECK(checker.getTotalChecksRun() == 2);
}
