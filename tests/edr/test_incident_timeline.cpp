#include <doctest/doctest.h>
#include <edr/IncidentTimeline.h>

#include <chrono>

using namespace ThreatOne::EDR;

TEST_CASE("IncidentTimeline - create incident returns valid ID") {
    IncidentTimeline timeline;
    auto id = timeline.createIncident("Ransomware Attack", "high");
    CHECK(!id.empty());
    CHECK(id.find("INC-") == 0);
}

TEST_CASE("IncidentTimeline - created incident has correct properties") {
    IncidentTimeline timeline;
    auto id = timeline.createIncident("Data Breach", "critical");
    auto incident = timeline.getIncident(id);

    REQUIRE(incident.has_value());
    CHECK(incident->name == "Data Breach");
    CHECK(incident->severity == "critical");
    CHECK(incident->status == "active");
    CHECK(incident->events.empty());
}

TEST_CASE("IncidentTimeline - multiple incidents get unique IDs") {
    IncidentTimeline timeline;
    auto id1 = timeline.createIncident("Incident 1", "low");
    auto id2 = timeline.createIncident("Incident 2", "medium");
    CHECK(id1 != id2);
}

TEST_CASE("IncidentTimeline - add event to incident") {
    IncidentTimeline timeline;
    auto incidentId = timeline.createIncident("Test Incident", "medium");

    TimelineEvent event;
    event.source = "FileMonitor";
    event.type = "file_access";
    event.description = "Suspicious file access detected";
    event.severity = "medium";
    event.relatedEntities = {"/tmp/malware.exe", "pid:1234"};

    CHECK(timeline.addEvent(incidentId, event));
}

TEST_CASE("IncidentTimeline - add event to non-existent incident fails") {
    IncidentTimeline timeline;
    TimelineEvent event;
    event.description = "test";
    CHECK_FALSE(timeline.addEvent("INC-99999", event));
}

TEST_CASE("IncidentTimeline - timeline is ordered chronologically") {
    IncidentTimeline timeline;
    auto incidentId = timeline.createIncident("Test Incident", "medium");
    auto now = std::chrono::steady_clock::now();

    TimelineEvent event1;
    event1.source = "ProcessMonitor";
    event1.type = "process_exec";
    event1.description = "Process started";
    event1.severity = "info";
    event1.timestamp = now + std::chrono::seconds(2);

    TimelineEvent event2;
    event2.source = "FileMonitor";
    event2.type = "file_write";
    event2.description = "File written";
    event2.severity = "low";
    event2.timestamp = now + std::chrono::seconds(1);

    TimelineEvent event3;
    event3.source = "NetworkMonitor";
    event3.type = "network";
    event3.description = "Connection made";
    event3.severity = "medium";
    event3.timestamp = now + std::chrono::seconds(3);

    timeline.addEvent(incidentId, event1);
    timeline.addEvent(incidentId, event2);
    timeline.addEvent(incidentId, event3);

    auto events = timeline.getTimeline(incidentId);
    REQUIRE(events.size() == 3);
    CHECK(events[0].description == "File written");
    CHECK(events[1].description == "Process started");
    CHECK(events[2].description == "Connection made");
}

TEST_CASE("IncidentTimeline - severity escalation on high events") {
    IncidentTimeline timeline;
    auto id = timeline.createIncident("Evolving Threat", "low");

    TimelineEvent lowEvent;
    lowEvent.source = "Monitor";
    lowEvent.type = "detection";
    lowEvent.description = "Minor anomaly";
    lowEvent.severity = "low";
    timeline.addEvent(id, lowEvent);

    auto incident = timeline.getIncident(id);
    CHECK(incident->severity == "low");

    TimelineEvent criticalEvent;
    criticalEvent.source = "Monitor";
    criticalEvent.type = "detection";
    criticalEvent.description = "Critical threat found";
    criticalEvent.severity = "critical";
    timeline.addEvent(id, criticalEvent);

    incident = timeline.getIncident(id);
    CHECK(incident->severity == "critical");
}

TEST_CASE("IncidentTimeline - severity does not decrease") {
    IncidentTimeline timeline;
    auto id = timeline.createIncident("Threat", "high");

    TimelineEvent lowEvent;
    lowEvent.source = "Monitor";
    lowEvent.type = "info";
    lowEvent.description = "Low event";
    lowEvent.severity = "low";
    timeline.addEvent(id, lowEvent);

    auto incident = timeline.getIncident(id);
    CHECK(incident->severity == "high");
}

TEST_CASE("IncidentTimeline - correlate events with shared entities") {
    IncidentTimeline timeline;
    auto id1 = timeline.createIncident("Incident 1", "medium");

    TimelineEvent event1;
    event1.source = "FileMonitor";
    event1.type = "file_write";
    event1.description = "Suspicious write";
    event1.severity = "medium";
    event1.relatedEntities = {"/tmp/malware", "pid:1234"};
    timeline.addEvent(id1, event1);

    // Query with event sharing an entity
    TimelineEvent queryEvent;
    queryEvent.source = "ProcessMonitor";
    queryEvent.type = "process_exec";
    queryEvent.description = "Related process";
    queryEvent.severity = "high";
    queryEvent.relatedEntities = {"pid:1234", "user:root"};

    auto correlations = timeline.correlateEvents(queryEvent);
    CHECK(!correlations.empty());
    CHECK(correlations[0] == id1);
}

TEST_CASE("IncidentTimeline - no correlation for unrelated events") {
    IncidentTimeline timeline;
    auto id1 = timeline.createIncident("Incident 1", "low");

    TimelineEvent event1;
    event1.source = "FileMonitor";
    event1.type = "file_write";
    event1.description = "Some event";
    event1.severity = "low";
    event1.relatedEntities = {"/home/user/doc.txt"};
    timeline.addEvent(id1, event1);

    TimelineEvent queryEvent;
    queryEvent.source = "Network";
    queryEvent.type = "connection";
    queryEvent.description = "Unrelated";
    queryEvent.severity = "low";
    queryEvent.relatedEntities = {"192.168.1.100"};

    auto correlations = timeline.correlateEvents(queryEvent);
    CHECK(correlations.empty());
}

TEST_CASE("IncidentTimeline - path prefix matching for correlation") {
    IncidentTimeline timeline;
    auto id1 = timeline.createIncident("File Incident", "medium");

    TimelineEvent event1;
    event1.source = "FileMonitor";
    event1.type = "file_write";
    event1.description = "Write in target dir";
    event1.severity = "medium";
    event1.relatedEntities = {"/home/user/sensitive/"};
    timeline.addEvent(id1, event1);

    TimelineEvent queryEvent;
    queryEvent.source = "FileMonitor";
    queryEvent.type = "file_read";
    queryEvent.description = "Read from same dir";
    queryEvent.severity = "low";
    queryEvent.relatedEntities = {"/home/user/sensitive/secrets.db"};

    auto correlations = timeline.correlateEvents(queryEvent);
    CHECK(!correlations.empty());
}

TEST_CASE("IncidentTimeline - active incidents excludes resolved") {
    IncidentTimeline timeline;
    (void)timeline.createIncident("Active 1", "high");
    (void)timeline.createIncident("Active 2", "low");
    auto id3 = timeline.createIncident("Resolved", "medium");
    timeline.resolveIncident(id3);

    auto active = timeline.getActiveIncidents();
    CHECK(active.size() == 2);

    // Should be sorted by severity
    CHECK(active[0].severity == "high");
    CHECK(active[1].severity == "low");
}

TEST_CASE("IncidentTimeline - resolve incident changes status") {
    IncidentTimeline timeline;
    auto id = timeline.createIncident("Test", "medium");
    CHECK(timeline.resolveIncident(id));

    auto incident = timeline.getIncident(id);
    CHECK(incident->status == "resolved");
}

TEST_CASE("IncidentTimeline - resolve non-existent incident") {
    IncidentTimeline timeline;
    CHECK_FALSE(timeline.resolveIncident("INC-99999"));
}

TEST_CASE("IncidentTimeline - clear all incidents") {
    IncidentTimeline timeline;
    (void)timeline.createIncident("Inc 1", "low");
    (void)timeline.createIncident("Inc 2", "high");

    timeline.clear();

    auto active = timeline.getActiveIncidents();
    CHECK(active.empty());
}
