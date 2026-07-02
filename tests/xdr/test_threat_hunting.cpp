#include <doctest/doctest.h>
#include <xdr/ThreatHunting.h>
#include <string>
#include <vector>

using namespace ThreatOne::XDR;

TEST_CASE("ThreatHunting - Create hypothesis") {
    ThreatHunting th;

    HuntingHypothesis h;
    h.name = "Lateral Movement via SMB";
    h.description = "Detect lateral movement using SMB protocol";
    h.technique = "T1021.002";
    h.dataSource = "network";
    h.indicators = {"smb", "445"};

    std::string id = th.createHypothesis(h);
    CHECK_FALSE(id.empty());
    CHECK(th.getHypothesisCount() == 1);
}

TEST_CASE("ThreatHunting - Get hypotheses by status") {
    ThreatHunting th;

    HuntingHypothesis h1;
    h1.name = "Test 1";
    h1.status = "active";
    th.createHypothesis(h1);

    HuntingHypothesis h2;
    h2.name = "Test 2";
    h2.status = "completed";
    th.createHypothesis(h2);

    auto active = th.getHypotheses("active");
    CHECK(active.size() == 1);

    auto all = th.getHypotheses("");
    CHECK(all.size() == 2);
}

TEST_CASE("ThreatHunting - Update hypothesis status") {
    ThreatHunting th;

    HuntingHypothesis h;
    h.name = "Test";
    std::string id = th.createHypothesis(h);

    CHECK(th.updateHypothesisStatus(id, "completed"));
    auto hypotheses = th.getHypotheses("completed");
    CHECK(hypotheses.size() == 1);

    CHECK_FALSE(th.updateHypothesisStatus("nonexistent", "archived"));
}

TEST_CASE("ThreatHunting - Add and manage IOCs") {
    ThreatHunting th;

    IOC ioc1;
    ioc1.type = "ip";
    ioc1.value = "203.0.113.50";
    ioc1.source = "threat_intel";
    ioc1.severity = "high";
    std::string id1 = th.addIOC(ioc1);

    IOC ioc2;
    ioc2.type = "hash";
    ioc2.value = "abc123def456";
    ioc2.source = "internal";
    ioc2.severity = "critical";
    std::string id2 = th.addIOC(ioc2);

    CHECK(th.getIOCCount() == 2);

    auto ipIOCs = th.getIOCs("ip");
    CHECK(ipIOCs.size() == 1);

    CHECK(th.deactivateIOC(id1));
    CHECK_FALSE(th.deactivateIOC("nonexistent"));
}

TEST_CASE("ThreatHunting - IOC sweep finds matches") {
    ThreatHunting th;

    IOC ioc;
    ioc.type = "ip";
    ioc.value = "203.0.113.50";
    ioc.source = "threat_intel";
    ioc.severity = "high";
    th.addIOC(ioc);

    std::vector<EndpointEvent> events;
    EndpointEvent e1;
    e1.id = "EVT-1";
    e1.endpointId = "EP-001";
    e1.eventType = "network";
    e1.details["ip"] = "203.0.113.50";
    events.push_back(e1);

    EndpointEvent e2;
    e2.id = "EVT-2";
    e2.endpointId = "EP-002";
    e2.eventType = "file_write";
    e2.details["ip"] = "10.0.0.1";
    events.push_back(e2);

    auto results = th.sweepIOCs(events);
    REQUIRE_FALSE(results.empty());
    CHECK(results[0].matchedEventIds.size() == 1);
    CHECK(results[0].severity == "high");
}

TEST_CASE("ThreatHunting - IOC sweep no matches") {
    ThreatHunting th;

    IOC ioc;
    ioc.type = "ip";
    ioc.value = "203.0.113.50";
    ioc.source = "threat_intel";
    ioc.severity = "high";
    th.addIOC(ioc);

    std::vector<EndpointEvent> events;
    EndpointEvent e1;
    e1.id = "EVT-1";
    e1.eventType = "file_write";
    e1.details["ip"] = "10.0.0.1";
    events.push_back(e1);

    auto results = th.sweepIOCs(events);
    CHECK(results.empty());
}

TEST_CASE("ThreatHunting - Behavioral pattern matching") {
    ThreatHunting th;

    BehavioralPattern pattern;
    pattern.name = "Recon then Exploit";
    pattern.eventSequence = {"recon", "exploit"};
    pattern.severity = "high";
    th.addBehavioralPattern(pattern);

    std::vector<EndpointEvent> events;
    EndpointEvent e1;
    e1.id = "EVT-1";
    e1.eventType = "recon_scan";
    e1.timestamp = "2024-01-15T10:00:00";
    events.push_back(e1);

    EndpointEvent e2;
    e2.id = "EVT-2";
    e2.eventType = "exploit_attempt";
    e2.timestamp = "2024-01-15T10:05:00";
    events.push_back(e2);

    auto results = th.matchBehavioralPatterns(events);
    REQUIRE_FALSE(results.empty());
    CHECK(results[0].summary.find("Recon then Exploit") != std::string::npos);
    CHECK(results[0].severity == "high");
}

TEST_CASE("ThreatHunting - Execute hunt with hypothesis") {
    ThreatHunting th;

    HuntingHypothesis h;
    h.name = "C2 Communication";
    h.indicators = {"beacon", "c2"};
    std::string hId = th.createHypothesis(h);

    std::vector<EndpointEvent> events;
    EndpointEvent e1;
    e1.id = "EVT-1";
    e1.eventType = "beacon_activity";
    events.push_back(e1);

    EndpointEvent e2;
    e2.id = "EVT-2";
    e2.eventType = "normal_process";
    events.push_back(e2);

    auto result = th.executeHunt(hId, events);
    CHECK_FALSE(result.id.empty());
    CHECK(result.matchedEventIds.size() >= 1);
    CHECK(result.confidence > 0.0);
    CHECK(th.getResultCount() == 1);
}

TEST_CASE("ThreatHunting - Execute hunt with nonexistent hypothesis") {
    ThreatHunting th;

    std::vector<EndpointEvent> events;
    auto result = th.executeHunt("nonexistent", events);
    CHECK(result.confidence == 0.0);
    CHECK(result.summary.find("not found") != std::string::npos);
}

TEST_CASE("ThreatHunting - Get hunt results by hypothesis") {
    ThreatHunting th;

    HuntingHypothesis h;
    h.name = "Test";
    h.indicators = {"malware"};
    std::string hId = th.createHypothesis(h);

    std::vector<EndpointEvent> events;
    EndpointEvent e;
    e.id = "EVT-1";
    e.eventType = "malware_detected";
    events.push_back(e);

    th.executeHunt(hId, events);

    auto results = th.getHuntResults(hId);
    CHECK(results.size() == 1);

    auto allResults = th.getHuntResults("");
    CHECK(allResults.size() == 1);
}
