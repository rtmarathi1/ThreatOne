#include <doctest/doctest.h>
#include <cloud/CloudPolicyManager.h>

using namespace ThreatOne::Cloud;

TEST_CASE("CloudPolicyManager - Distribute policy") {
    CloudPolicyManager mgr;

    PolicyInfo policy;
    policy.name = "Antivirus Config";
    policy.version = 1;
    policy.content = "{\"scan_interval\": 3600}";

    std::string id = mgr.distributePolicy(policy);
    CHECK_FALSE(id.empty());
    CHECK(id.find("POL-") == 0);

    auto policies = mgr.getPolicies();
    CHECK(policies.size() == 1);
    CHECK(policies[0].name == "Antivirus Config");
}

TEST_CASE("CloudPolicyManager - Acknowledge policy") {
    CloudPolicyManager mgr;

    PolicyInfo policy;
    policy.name = "Test Policy";
    std::string id = mgr.distributePolicy(policy);

    CHECK(mgr.acknowledgePolicy(id, "endpoint-001"));
    CHECK(mgr.acknowledgePolicy(id, "endpoint-002"));
    CHECK(mgr.isPolicyAcknowledgedBy(id, "endpoint-001"));
    CHECK_FALSE(mgr.isPolicyAcknowledgedBy(id, "endpoint-003"));
}

TEST_CASE("CloudPolicyManager - Acknowledge idempotent") {
    CloudPolicyManager mgr;

    PolicyInfo policy;
    policy.name = "Idempotent";
    std::string id = mgr.distributePolicy(policy);

    CHECK(mgr.acknowledgePolicy(id, "ep-001"));
    CHECK(mgr.acknowledgePolicy(id, "ep-001"));

    auto acks = mgr.getAcknowledgments(id);
    CHECK(acks.size() == 1);
}

TEST_CASE("CloudPolicyManager - Acknowledge nonexistent fails") {
    CloudPolicyManager mgr;
    CHECK_FALSE(mgr.acknowledgePolicy("nonexistent", "ep-001"));
}

TEST_CASE("CloudPolicyManager - Policy versions") {
    CloudPolicyManager mgr;

    PolicyInfo policy;
    policy.name = "Versioned Policy";
    policy.content = "v1 content";
    std::string id = mgr.distributePolicy(policy);

    mgr.createPolicyVersion(id, "v2 content");
    mgr.createPolicyVersion(id, "v3 content");

    auto versions = mgr.getPolicyVersions(id);
    CHECK(versions.size() == 3);

    CHECK(mgr.getActivePolicyVersion(id) == 1);  // First version is active
    CHECK(mgr.activatePolicyVersion(id, 2));
    CHECK(mgr.getActivePolicyVersion(id) == 2);
}

TEST_CASE("CloudPolicyManager - Remove policy") {
    CloudPolicyManager mgr;

    PolicyInfo policy;
    policy.name = "To Remove";
    std::string id = mgr.distributePolicy(policy);

    CHECK(mgr.removePolicy(id));
    CHECK(mgr.getPolicyCount() == 0);
    CHECK_FALSE(mgr.removePolicy(id));
}

TEST_CASE("CloudPolicyManager - Policy count") {
    CloudPolicyManager mgr;

    PolicyInfo p1, p2;
    p1.name = "Policy 1";
    p2.name = "Policy 2";
    mgr.distributePolicy(p1);
    mgr.distributePolicy(p2);

    CHECK(mgr.getPolicyCount() == 2);
}
