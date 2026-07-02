#include <doctest/doctest.h>
#include <xdr/AutomatedInvestigation.h>
#include <string>
#include <vector>
#include <map>

using namespace ThreatOne::XDR;

TEST_CASE("AutomatedInvestigation - Default playbooks registered") {
    AutomatedInvestigation ai;

    auto playbooks = ai.getPlaybooks();
    CHECK(playbooks.size() >= 2);  // default and malware_response
}

TEST_CASE("AutomatedInvestigation - Register custom playbook") {
    AutomatedInvestigation ai;

    InvestigationPlaybook pb;
    pb.name = "custom_playbook";
    pb.description = "Custom investigation";
    pb.triggerCondition = "any";
    pb.steps = {
        {"Step 1", "gather_context", "pending", ""},
        {"Step 2", "check_reputation", "pending", ""}
    };

    std::string id = ai.registerPlaybook(pb);
    CHECK_FALSE(id.empty());

    auto playbook = ai.getPlaybook("custom_playbook");
    CHECK(playbook.name == "custom_playbook");
    CHECK(playbook.steps.size() == 2);
}

TEST_CASE("AutomatedInvestigation - Start investigation with default playbook") {
    AutomatedInvestigation ai;

    Correlation corr;
    corr.id = "CORR-1";
    corr.eventIds = {"EVT-1", "EVT-2"};
    corr.severity = "high";
    corr.confidence = 0.8;

    std::map<std::string, EndpointEvent> events;
    EndpointEvent e1;
    e1.id = "EVT-1";
    e1.endpointId = "EP-001";
    e1.eventType = "malware";
    events["EVT-1"] = e1;

    EndpointEvent e2;
    e2.id = "EVT-2";
    e2.endpointId = "EP-001";
    e2.eventType = "c2_comm";
    events["EVT-2"] = e2;

    std::string invId = ai.startInvestigation("CORR-1", "default", corr, events);
    CHECK_FALSE(invId.empty());

    auto result = ai.getInvestigationResult(invId);
    CHECK(result.investigationId == invId);
    CHECK(result.correlationId == "CORR-1");
    CHECK(result.status == InvestigationStatus::InProgress);
    CHECK(result.playbook == "default");
    CHECK_FALSE(result.findings.empty());
    CHECK_FALSE(result.executedSteps.empty());
}

TEST_CASE("AutomatedInvestigation - Investigation generates evidence from events") {
    AutomatedInvestigation ai;

    Correlation corr;
    corr.id = "CORR-1";
    corr.eventIds = {"EVT-1"};
    corr.severity = "medium";
    corr.confidence = 0.5;

    std::map<std::string, EndpointEvent> events;
    EndpointEvent e1;
    e1.id = "EVT-1";
    e1.endpointId = "EP-001";
    e1.eventType = "suspicious_process";
    events["EVT-1"] = e1;

    std::string invId = ai.startInvestigation("CORR-1", "malware_response", corr, events);
    auto result = ai.getInvestigationResult(invId);
    CHECK_FALSE(result.evidence.empty());
}

TEST_CASE("AutomatedInvestigation - Get active investigations") {
    AutomatedInvestigation ai;

    Correlation corr;
    corr.id = "CORR-1";
    corr.eventIds = {"EVT-1"};
    corr.severity = "high";
    corr.confidence = 0.7;

    std::map<std::string, EndpointEvent> events;

    ai.startInvestigation("CORR-1", "default", corr, events);
    ai.startInvestigation("CORR-2", "default", corr, events);

    auto active = ai.getActiveInvestigations();
    CHECK(active.size() == 2);
    CHECK(ai.getActiveCount() == 2);
    CHECK(ai.getInvestigationCount() == 2);
}

TEST_CASE("AutomatedInvestigation - Get nonexistent investigation returns empty") {
    AutomatedInvestigation ai;
    auto result = ai.getInvestigationResult("nonexistent");
    CHECK(result.investigationId.empty());
}

TEST_CASE("AutomatedInvestigation - High confidence recommends response") {
    AutomatedInvestigation ai;

    Correlation corr;
    corr.id = "CORR-1";
    corr.eventIds = {"EVT-1", "EVT-2"};
    corr.severity = "critical";
    corr.confidence = 0.9;

    std::map<std::string, EndpointEvent> events;

    std::string invId = ai.startInvestigation("CORR-1", "default", corr, events);
    auto result = ai.getInvestigationResult(invId);

    // High confidence should trigger recommendation
    bool hasRecommendation = false;
    for (const auto& finding : result.findings) {
        if (finding.find("automated response recommended") != std::string::npos) {
            hasRecommendation = true;
        }
    }
    CHECK(hasRecommendation);
}
