#include <doctest/doctest.h>
#include <xdr/XDREngine.h>
#include <string>

using namespace ThreatOne::XDR;

TEST_CASE("XDREngine - Submit endpoint event") {
    XDREngine engine;

    EndpointEvent event;
    event.endpointId = "EP-001";
    event.eventType = "process_creation";
    event.timestamp = "2024-01-15T10:00:00";
    event.severity = "medium";
    event.details["process"] = "cmd.exe";

    std::string id = engine.submitEndpointEvent(event);
    CHECK_FALSE(id.empty());
}

TEST_CASE("XDREngine - Submit multiple events returns unique IDs") {
    XDREngine engine;

    EndpointEvent event1;
    event1.endpointId = "EP-001";
    event1.eventType = "file_write";
    event1.timestamp = "2024-01-15T10:00:00";
    event1.severity = "low";

    EndpointEvent event2;
    event2.endpointId = "EP-001";
    event2.eventType = "network_connection";
    event2.timestamp = "2024-01-15T10:01:00";
    event2.severity = "medium";

    std::string id1 = engine.submitEndpointEvent(event1);
    std::string id2 = engine.submitEndpointEvent(event2);

    CHECK(id1 != id2);
}

TEST_CASE("XDREngine - Correlate events on same endpoint within time window") {
    XDREngine engine;

    EndpointEvent event1;
    event1.endpointId = "EP-001";
    event1.eventType = "process_creation";
    event1.timestamp = "2024-01-15T10:00:00";
    event1.severity = "low";

    EndpointEvent event2;
    event2.endpointId = "EP-001";
    event2.eventType = "file_modification";
    event2.timestamp = "2024-01-15T10:02:00";
    event2.severity = "medium";

    EndpointEvent event3;
    event3.endpointId = "EP-001";
    event3.eventType = "network_exfiltration";
    event3.timestamp = "2024-01-15T10:03:00";
    event3.severity = "high";

    std::string id1 = engine.submitEndpointEvent(event1);
    std::string id2 = engine.submitEndpointEvent(event2);
    std::string id3 = engine.submitEndpointEvent(event3);

    auto correlations = engine.correlateEvents({id1, id2, id3});
    REQUIRE_FALSE(correlations.empty());
    CHECK(correlations[0].eventIds.size() == 3);
    CHECK_FALSE(correlations[0].id.empty());
    CHECK(correlations[0].severity == "high");
}

TEST_CASE("XDREngine - Events from different endpoints do not correlate together") {
    XDREngine engine;

    EndpointEvent event1;
    event1.endpointId = "EP-001";
    event1.eventType = "process_creation";
    event1.timestamp = "2024-01-15T10:00:00";
    event1.severity = "low";

    EndpointEvent event2;
    event2.endpointId = "EP-002";
    event2.eventType = "file_modification";
    event2.timestamp = "2024-01-15T10:02:00";
    event2.severity = "medium";

    std::string id1 = engine.submitEndpointEvent(event1);
    std::string id2 = engine.submitEndpointEvent(event2);

    // Single event per endpoint - no correlation (need 2+ on same endpoint)
    auto correlations = engine.correlateEvents({id1, id2});
    CHECK(correlations.empty());
}

TEST_CASE("XDREngine - Escalating severity detected as multi-stage attack") {
    XDREngine engine;

    EndpointEvent event1;
    event1.endpointId = "EP-001";
    event1.eventType = "recon";
    event1.timestamp = "2024-01-15T10:00:00";
    event1.severity = "low";

    EndpointEvent event2;
    event2.endpointId = "EP-001";
    event2.eventType = "exploitation";
    event2.timestamp = "2024-01-15T10:01:00";
    event2.severity = "medium";

    EndpointEvent event3;
    event3.endpointId = "EP-001";
    event3.eventType = "exfiltration";
    event3.timestamp = "2024-01-15T10:02:00";
    event3.severity = "critical";

    std::string id1 = engine.submitEndpointEvent(event1);
    std::string id2 = engine.submitEndpointEvent(event2);
    std::string id3 = engine.submitEndpointEvent(event3);

    auto correlations = engine.correlateEvents({id1, id2, id3});
    REQUIRE_FALSE(correlations.empty());
    CHECK(correlations[0].description.find("Multi-stage") != std::string::npos);
    CHECK(correlations[0].confidence > 0.5);
}

TEST_CASE("XDREngine - Empty event list returns no correlations") {
    XDREngine engine;
    auto correlations = engine.correlateEvents({});
    CHECK(correlations.empty());
}

TEST_CASE("XDREngine - Nonexistent event IDs return no correlations") {
    XDREngine engine;
    auto correlations = engine.correlateEvents({"nonexistent-1", "nonexistent-2"});
    CHECK(correlations.empty());
}

TEST_CASE("XDREngine - Cross-source correlation merges alerts from different sources") {
    XDREngine engine;

    CrossSourceAlert alert1;
    alert1.id = "CSA-001";
    alert1.source = AlertSource::Email;
    alert1.originalAlertId = "EMAIL-ALERT-1";
    alert1.normalizedSeverity = "high";
    alert1.description = "Phishing email detected";
    alert1.timestamp = "2024-01-15T10:00:00";

    CrossSourceAlert alert2;
    alert2.id = "CSA-002";
    alert2.source = AlertSource::Endpoint;
    alert2.originalAlertId = "EP-ALERT-1";
    alert2.normalizedSeverity = "high";
    alert2.description = "Malware execution after email click";
    alert2.timestamp = "2024-01-15T10:05:00";

    CrossSourceAlert alert3;
    alert3.id = "CSA-003";
    alert3.source = AlertSource::Network;
    alert3.originalAlertId = "NET-ALERT-1";
    alert3.normalizedSeverity = "critical";
    alert3.description = "C2 communication detected";
    alert3.timestamp = "2024-01-15T10:10:00";

    auto correlations = engine.correlateAcrossSources({alert1, alert2, alert3});
    REQUIRE_FALSE(correlations.empty());
    CHECK(correlations[0].eventIds.size() == 3);
    CHECK(correlations[0].description.find("Cross-source") != std::string::npos);
    CHECK(correlations[0].severity == "critical");
}

TEST_CASE("XDREngine - Cross-source with single source returns no correlation") {
    XDREngine engine;

    CrossSourceAlert alert1;
    alert1.id = "CSA-001";
    alert1.source = AlertSource::Endpoint;
    alert1.originalAlertId = "EP-1";
    alert1.normalizedSeverity = "medium";

    // Single alert - not enough for correlation
    auto correlations = engine.correlateAcrossSources({alert1});
    CHECK(correlations.empty());
}

TEST_CASE("XDREngine - Cross-source creates incident") {
    XDREngine engine;

    CrossSourceAlert alert1;
    alert1.id = "CSA-001";
    alert1.source = AlertSource::Identity;
    alert1.originalAlertId = "ID-1";
    alert1.normalizedSeverity = "high";
    alert1.timestamp = "2024-01-15T10:00:00";

    CrossSourceAlert alert2;
    alert2.id = "CSA-002";
    alert2.source = AlertSource::Cloud;
    alert2.originalAlertId = "CLOUD-1";
    alert2.normalizedSeverity = "high";
    alert2.timestamp = "2024-01-15T10:01:00";

    engine.correlateAcrossSources({alert1, alert2});

    auto incidents = engine.getIncidents();
    REQUIRE_FALSE(incidents.empty());
    CHECK(incidents[0].status == "open");
    CHECK_FALSE(incidents[0].correlationIds.empty());
}

TEST_CASE("XDREngine - Automated investigation creates findings") {
    XDREngine engine;

    // First create a correlation
    EndpointEvent event1;
    event1.endpointId = "EP-001";
    event1.eventType = "malware_detected";
    event1.timestamp = "2024-01-15T10:00:00";
    event1.severity = "high";

    EndpointEvent event2;
    event2.endpointId = "EP-001";
    event2.eventType = "lateral_movement";
    event2.timestamp = "2024-01-15T10:01:00";
    event2.severity = "critical";

    std::string id1 = engine.submitEndpointEvent(event1);
    std::string id2 = engine.submitEndpointEvent(event2);

    auto correlations = engine.correlateEvents({id1, id2});
    REQUIRE_FALSE(correlations.empty());

    std::string invId = engine.startAutomatedInvestigation(correlations[0].id, "malware_response");

    CHECK_FALSE(invId.empty());

    auto inv = engine.getInvestigation(invId);
    CHECK(inv.id == invId);
    CHECK(inv.correlationId == correlations[0].id);
    CHECK(inv.status == InvestigationStatus::InProgress);
    CHECK(inv.playbook == "malware_response");
    CHECK_FALSE(inv.findings.empty());
    CHECK_FALSE(inv.evidence.empty());
}

TEST_CASE("XDREngine - Get investigation for nonexistent ID returns empty") {
    XDREngine engine;
    auto inv = engine.getInvestigation("nonexistent");
    CHECK(inv.id.empty());
}

TEST_CASE("XDREngine - Get active investigations") {
    XDREngine engine;

    EndpointEvent event1;
    event1.endpointId = "EP-001";
    event1.eventType = "suspicious";
    event1.timestamp = "2024-01-15T10:00:00";
    event1.severity = "medium";

    EndpointEvent event2;
    event2.endpointId = "EP-001";
    event2.eventType = "malicious";
    event2.timestamp = "2024-01-15T10:01:00";
    event2.severity = "high";

    std::string id1 = engine.submitEndpointEvent(event1);
    std::string id2 = engine.submitEndpointEvent(event2);

    auto correlations = engine.correlateEvents({id1, id2});
    REQUIRE_FALSE(correlations.empty());

    engine.startAutomatedInvestigation(correlations[0].id, "default");

    auto active = engine.getActiveInvestigations();
    CHECK(active.size() == 1);
    CHECK(active[0].status == InvestigationStatus::InProgress);
}

TEST_CASE("XDREngine - Execute response action with valid target") {
    XDREngine engine;

    ResponseAction action;
    action.type = ActionType::IsolateEndpoint;
    action.target = "EP-001";
    action.timestamp = "2024-01-15T10:00:00";

    std::string actionId = engine.executeResponseAction(action);
    CHECK_FALSE(actionId.empty());

    auto actions = engine.getResponseActions();
    REQUIRE(actions.size() == 1);
    CHECK(actions[0].id == actionId);
    CHECK(actions[0].status == ActionStatus::Completed);
    CHECK(actions[0].target == "EP-001");
    CHECK(actions[0].type == ActionType::IsolateEndpoint);
}

TEST_CASE("XDREngine - Execute response action with empty target fails") {
    XDREngine engine;

    ResponseAction action;
    action.type = ActionType::BlockIP;
    action.target = "";

    std::string actionId = engine.executeResponseAction(action);
    CHECK_FALSE(actionId.empty());

    auto actions = engine.getResponseActions();
    REQUIRE(actions.size() == 1);
    CHECK(actions[0].status == ActionStatus::Failed);
}

TEST_CASE("XDREngine - Multiple response actions") {
    XDREngine engine;

    ResponseAction action1;
    action1.type = ActionType::BlockIP;
    action1.target = "192.168.1.100";

    ResponseAction action2;
    action2.type = ActionType::DisableUser;
    action2.target = "compromised_user";

    ResponseAction action3;
    action3.type = ActionType::KillProcess;
    action3.target = "malware.exe";

    engine.executeResponseAction(action1);
    engine.executeResponseAction(action2);
    engine.executeResponseAction(action3);

    auto actions = engine.getResponseActions();
    CHECK(actions.size() == 3);
}

TEST_CASE("XDREngine - getCorrelations returns all stored correlations") {
    XDREngine engine;

    EndpointEvent event1;
    event1.endpointId = "EP-001";
    event1.eventType = "a";
    event1.timestamp = "2024-01-15T10:00:00";
    event1.severity = "medium";

    EndpointEvent event2;
    event2.endpointId = "EP-001";
    event2.eventType = "b";
    event2.timestamp = "2024-01-15T10:01:00";
    event2.severity = "high";

    std::string id1 = engine.submitEndpointEvent(event1);
    std::string id2 = engine.submitEndpointEvent(event2);

    engine.correlateEvents({id1, id2});

    auto all = engine.getCorrelations();
    CHECK(all.size() == 1);
}

TEST_CASE("XDREngine - startInvestigation delegates to startAutomatedInvestigation") {
    XDREngine engine;

    EndpointEvent event1;
    event1.endpointId = "EP-001";
    event1.eventType = "x";
    event1.timestamp = "2024-01-15T10:00:00";
    event1.severity = "high";

    EndpointEvent event2;
    event2.endpointId = "EP-001";
    event2.eventType = "y";
    event2.timestamp = "2024-01-15T10:01:00";
    event2.severity = "critical";

    std::string id1 = engine.submitEndpointEvent(event1);
    std::string id2 = engine.submitEndpointEvent(event2);

    auto correlations = engine.correlateEvents({id1, id2});
    REQUIRE_FALSE(correlations.empty());

    std::string invId = engine.startInvestigation(correlations[0].id);
    CHECK_FALSE(invId.empty());

    auto inv = engine.getInvestigation(invId);
    CHECK(inv.playbook == "default");
}
