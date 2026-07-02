#include <doctest/doctest.h>
#include <xdr/CloudCorrelation.h>
#include <string>
#include <vector>

using namespace ThreatOne::XDR;

TEST_CASE("CloudCorrelation - Submit cloud event") {
    CloudCorrelation cc;

    CloudEvent event;
    event.provider = "aws";
    event.service = "s3";
    event.eventType = "api_call";
    event.principal = "admin-user";
    event.resource = "my-bucket";
    event.action = "PutObject";
    event.region = "us-east-1";
    event.timestamp = "2024-01-15T10:00:00";
    event.severity = "low";

    std::string id = cc.submitCloudEvent(event);
    CHECK_FALSE(id.empty());
    CHECK(cc.getEventCount() == 1);
}

TEST_CASE("CloudCorrelation - Get events by provider") {
    CloudCorrelation cc;

    CloudEvent e1;
    e1.provider = "aws";
    e1.eventType = "api_call";
    e1.principal = "user1";
    cc.submitCloudEvent(e1);

    CloudEvent e2;
    e2.provider = "azure";
    e2.eventType = "resource_modified";
    e2.principal = "user2";
    cc.submitCloudEvent(e2);

    auto awsEvents = cc.getCloudEvents("aws");
    CHECK(awsEvents.size() == 1);

    auto allEvents = cc.getCloudEvents("");
    CHECK(allEvents.size() == 2);
}

TEST_CASE("CloudCorrelation - Detect privilege escalation threat") {
    CloudCorrelation cc;

    // Multiple IAM changes by same principal
    for (int i = 0; i < 3; i++) {
        CloudEvent event;
        event.provider = "aws";
        event.eventType = "iam_change";
        event.principal = "suspicious-user";
        event.action = "AttachPolicy";
        event.resource = "policy-" + std::to_string(i);
        cc.submitCloudEvent(event);
    }

    auto threats = cc.detectCloudThreats();
    REQUIRE_FALSE(threats.empty());
    CHECK(threats[0].threatType == "privilege_escalation");
    CHECK(threats[0].confidence > 0.5);
}

TEST_CASE("CloudCorrelation - Detect anomalous activity") {
    CloudCorrelation cc;

    for (int i = 0; i < 3; i++) {
        CloudEvent event;
        event.provider = "aws";
        event.eventType = "api_call";
        event.principal = "attacker";
        event.anomalous = true;
        cc.submitCloudEvent(event);
    }

    auto threats = cc.detectCloudThreats();
    bool foundResourceHijack = false;
    for (const auto& t : threats) {
        if (t.threatType == "resource_hijack") {
            foundResourceHijack = true;
            break;
        }
    }
    CHECK(foundResourceHijack);
}

TEST_CASE("CloudCorrelation - Get IAM changes") {
    CloudCorrelation cc;

    CloudEvent e1;
    e1.provider = "aws";
    e1.eventType = "iam_change";
    e1.principal = "admin";
    e1.action = "CreateRole";
    cc.submitCloudEvent(e1);

    CloudEvent e2;
    e2.provider = "aws";
    e2.eventType = "api_call";
    e2.principal = "admin";
    e2.action = "ListBuckets";
    cc.submitCloudEvent(e2);

    auto iamChanges = cc.getIAMChanges("");
    CHECK(iamChanges.size() == 1);

    auto adminIam = cc.getIAMChanges("admin");
    CHECK(adminIam.size() == 1);
}

TEST_CASE("CloudCorrelation - Is privilege escalation") {
    CloudCorrelation cc;

    CloudEvent event;
    event.provider = "aws";
    event.eventType = "iam_change";
    event.principal = "attacker";
    event.action = "attach_policy_admin";
    std::string id = cc.submitCloudEvent(event);

    CHECK(cc.isPrivilegeEscalation(id));
}

TEST_CASE("CloudCorrelation - Cross-provider correlation") {
    CloudCorrelation cc;

    CloudEvent e1;
    e1.provider = "aws";
    e1.eventType = "api_call";
    e1.principal = "shared-user";
    cc.submitCloudEvent(e1);

    CloudEvent e2;
    e2.provider = "azure";
    e2.eventType = "api_call";
    e2.principal = "shared-user";
    cc.submitCloudEvent(e2);

    auto correlations = cc.correlateAcrossProviders();
    REQUIRE_FALSE(correlations.empty());
    CHECK(correlations[0].eventIds.size() == 2);
    CHECK(correlations[0].description.find("shared-user") != std::string::npos);
}

TEST_CASE("CloudCorrelation - Event count by provider") {
    CloudCorrelation cc;

    CloudEvent e1;
    e1.provider = "aws";
    e1.eventType = "api_call";
    cc.submitCloudEvent(e1);

    CloudEvent e2;
    e2.provider = "aws";
    e2.eventType = "api_call";
    cc.submitCloudEvent(e2);

    CloudEvent e3;
    e3.provider = "gcp";
    e3.eventType = "api_call";
    cc.submitCloudEvent(e3);

    CHECK(cc.getEventCountByProvider("aws") == 2);
    CHECK(cc.getEventCountByProvider("gcp") == 1);
    CHECK(cc.getEventCountByProvider("azure") == 0);
}
