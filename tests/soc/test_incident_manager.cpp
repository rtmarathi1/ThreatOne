#include <doctest/doctest.h>
#include <soc/IncidentManager.h>
#include <string>

using namespace ThreatOne::SOC;

TEST_CASE("IncidentManager - Create incident") {
    IncidentManager mgr;

    IncidentInfo info;
    info.title = "Ransomware Attack";
    info.description = "Multiple endpoints encrypted";
    info.severity = IncidentSeverity::Critical;

    std::string id = mgr.createIncident(info);
    CHECK_FALSE(id.empty());
    CHECK(id.find("INC-") == 0);
}

TEST_CASE("IncidentManager - Create multiple incidents") {
    IncidentManager mgr;

    IncidentInfo info1;
    info1.title = "Incident 1";
    IncidentInfo info2;
    info2.title = "Incident 2";

    std::string id1 = mgr.createIncident(info1);
    std::string id2 = mgr.createIncident(info2);
    CHECK(id1 != id2);
}

TEST_CASE("IncidentManager - Update incident status") {
    IncidentManager mgr;

    IncidentInfo info;
    info.title = "Status test";
    std::string id = mgr.createIncident(info);

    CHECK(mgr.updateIncidentStatus(id, IncidentStatus::Investigating));
    CHECK(mgr.updateIncidentStatus(id, IncidentStatus::Contained));
    CHECK(mgr.updateIncidentStatus(id, IncidentStatus::Closed));

    // Cannot modify closed
    CHECK_FALSE(mgr.updateIncidentStatus(id, IncidentStatus::Open));
}

TEST_CASE("IncidentManager - Status update on nonexistent fails") {
    IncidentManager mgr;
    CHECK_FALSE(mgr.updateIncidentStatus("nonexistent", IncidentStatus::Investigating));
}

TEST_CASE("IncidentManager - Assign lead analyst") {
    IncidentManager mgr;

    IncidentInfo info;
    info.title = "Lead test";
    std::string id = mgr.createIncident(info);

    CHECK(mgr.assignLead(id, "analyst-01"));
    auto inc = mgr.getIncident(id);
    CHECK(inc.leadAnalyst == "analyst-01");

    CHECK_FALSE(mgr.assignLead("nonexistent", "analyst-01"));
}

TEST_CASE("IncidentManager - Add and remove cases") {
    IncidentManager mgr;

    IncidentInfo info;
    info.title = "Case association test";
    std::string id = mgr.createIncident(info);

    CHECK(mgr.addCaseToIncident(id, "CASE-001"));
    CHECK(mgr.addCaseToIncident(id, "CASE-002"));
    // Cannot add duplicate
    CHECK_FALSE(mgr.addCaseToIncident(id, "CASE-001"));

    auto inc = mgr.getIncident(id);
    CHECK(inc.caseIds.size() == 2);

    CHECK(mgr.removeCaseFromIncident(id, "CASE-001"));
    inc = mgr.getIncident(id);
    CHECK(inc.caseIds.size() == 1);

    // Remove nonexistent case
    CHECK_FALSE(mgr.removeCaseFromIncident(id, "CASE-999"));
}

TEST_CASE("IncidentManager - Add case to nonexistent incident fails") {
    IncidentManager mgr;
    CHECK_FALSE(mgr.addCaseToIncident("nonexistent", "CASE-001"));
}

TEST_CASE("IncidentManager - Incident exists check") {
    IncidentManager mgr;

    IncidentInfo info;
    info.title = "Exists test";
    std::string id = mgr.createIncident(info);

    CHECK(mgr.incidentExists(id));
    CHECK_FALSE(mgr.incidentExists("nonexistent"));
}

TEST_CASE("IncidentManager - Get all incidents") {
    IncidentManager mgr;

    IncidentInfo info1;
    info1.title = "Incident 1";
    info1.severity = IncidentSeverity::High;
    mgr.createIncident(info1);

    IncidentInfo info2;
    info2.title = "Incident 2";
    info2.severity = IncidentSeverity::Low;
    mgr.createIncident(info2);

    auto all = mgr.getAllIncidents();
    CHECK(all.size() == 2);
}

TEST_CASE("IncidentManager - Get incidents by severity") {
    IncidentManager mgr;

    IncidentInfo info1;
    info1.title = "Critical 1";
    info1.severity = IncidentSeverity::Critical;
    mgr.createIncident(info1);

    IncidentInfo info2;
    info2.title = "Low 1";
    info2.severity = IncidentSeverity::Low;
    mgr.createIncident(info2);

    IncidentInfo info3;
    info3.title = "Critical 2";
    info3.severity = IncidentSeverity::Critical;
    mgr.createIncident(info3);

    auto critical = mgr.getIncidentsBySeverity(IncidentSeverity::Critical);
    CHECK(critical.size() == 2);

    auto low = mgr.getIncidentsBySeverity(IncidentSeverity::Low);
    CHECK(low.size() == 1);
}

TEST_CASE("IncidentManager - Get open incidents") {
    IncidentManager mgr;

    IncidentInfo info1;
    info1.title = "Open";
    std::string id1 = mgr.createIncident(info1);

    IncidentInfo info2;
    info2.title = "Closed";
    std::string id2 = mgr.createIncident(info2);
    mgr.updateIncidentStatus(id2, IncidentStatus::Closed);

    auto open = mgr.getOpenIncidents();
    CHECK(open.size() == 1);
    CHECK(open[0].title == "Open");
}

TEST_CASE("IncidentManager - Incident count") {
    IncidentManager mgr;
    CHECK(mgr.getIncidentCount() == 0);

    IncidentInfo info;
    info.title = "Test";
    mgr.createIncident(info);
    CHECK(mgr.getIncidentCount() == 1);
}

TEST_CASE("IncidentManager - Update severity") {
    IncidentManager mgr;

    IncidentInfo info;
    info.title = "Severity test";
    info.severity = IncidentSeverity::Low;
    std::string id = mgr.createIncident(info);

    CHECK(mgr.updateSeverity(id, IncidentSeverity::Critical));
    auto inc = mgr.getIncident(id);
    CHECK(inc.severity == IncidentSeverity::Critical);

    CHECK_FALSE(mgr.updateSeverity("nonexistent", IncidentSeverity::High));
}
