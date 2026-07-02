#include <doctest/doctest.h>
#include <soc/CaseManager.h>
#include <string>

using namespace ThreatOne::SOC;

TEST_CASE("CaseManager - Create case") {
    CaseManager mgr;

    CaseInfo info;
    info.title = "Suspicious login";
    info.description = "Multiple failed logins detected";
    info.severity = "high";

    std::string id = mgr.createCase(info);
    CHECK_FALSE(id.empty());
    CHECK(id.find("CASE-") == 0);
}

TEST_CASE("CaseManager - Create multiple cases returns unique IDs") {
    CaseManager mgr;

    CaseInfo info1;
    info1.title = "Case 1";
    CaseInfo info2;
    info2.title = "Case 2";

    std::string id1 = mgr.createCase(info1);
    std::string id2 = mgr.createCase(info2);
    CHECK(id1 != id2);
}

TEST_CASE("CaseManager - Assign case") {
    CaseManager mgr;

    CaseInfo info;
    info.title = "Assign test";
    std::string id = mgr.createCase(info);

    CHECK(mgr.assignCase(id, "analyst-01"));
    CHECK_FALSE(mgr.assignCase("nonexistent", "analyst-01"));

    auto c = mgr.getCase(id);
    CHECK(c.assignee == "analyst-01");
}

TEST_CASE("CaseManager - Escalate case") {
    CaseManager mgr;

    CaseInfo info;
    info.title = "Escalation test";
    std::string id = mgr.createCase(info);

    CHECK(mgr.escalate(id, "Potential APT"));
    CHECK_FALSE(mgr.escalate("nonexistent", "reason"));

    auto c = mgr.getCase(id);
    CHECK(c.status == CaseStatus::Escalated);
    CHECK(c.escalationReason == "Potential APT");
}

TEST_CASE("CaseManager - Status transitions") {
    CaseManager mgr;

    CaseInfo info;
    info.title = "Transition test";
    std::string id = mgr.createCase(info);

    CHECK(mgr.updateCaseStatus(id, CaseStatus::Investigating));
    CHECK(mgr.updateCaseStatus(id, CaseStatus::Resolved));
    CHECK(mgr.updateCaseStatus(id, CaseStatus::Closed));

    // Cannot reopen
    CHECK_FALSE(mgr.updateCaseStatus(id, CaseStatus::Open));
}

TEST_CASE("CaseManager - Resolved can only go to closed") {
    CaseManager mgr;

    CaseInfo info;
    info.title = "Resolved transition";
    std::string id = mgr.createCase(info);

    CHECK(mgr.updateCaseStatus(id, CaseStatus::Resolved));
    CHECK_FALSE(mgr.updateCaseStatus(id, CaseStatus::Investigating));
    CHECK(mgr.updateCaseStatus(id, CaseStatus::Closed));
}

TEST_CASE("CaseManager - Case existence check") {
    CaseManager mgr;

    CaseInfo info;
    info.title = "Exists test";
    std::string id = mgr.createCase(info);

    CHECK(mgr.caseExists(id));
    CHECK_FALSE(mgr.caseExists("nonexistent"));
}

TEST_CASE("CaseManager - Get cases by status") {
    CaseManager mgr;

    CaseInfo info1;
    info1.title = "Open case";
    mgr.createCase(info1);

    CaseInfo info2;
    info2.title = "Closed case";
    std::string id2 = mgr.createCase(info2);
    mgr.updateCaseStatus(id2, CaseStatus::Resolved);
    mgr.updateCaseStatus(id2, CaseStatus::Closed);

    auto open = mgr.getCasesByStatus(CaseStatus::Open);
    auto closed = mgr.getCasesByStatus(CaseStatus::Closed);
    CHECK(open.size() == 1);
    CHECK(closed.size() == 1);
}

TEST_CASE("CaseManager - Get cases by assignee") {
    CaseManager mgr;

    CaseInfo info1;
    info1.title = "Case A";
    std::string id1 = mgr.createCase(info1);
    mgr.assignCase(id1, "analyst-01");

    CaseInfo info2;
    info2.title = "Case B";
    std::string id2 = mgr.createCase(info2);
    mgr.assignCase(id2, "analyst-02");

    auto cases = mgr.getCasesByAssignee("analyst-01");
    CHECK(cases.size() == 1);
    CHECK(cases[0].title == "Case A");
}

TEST_CASE("CaseManager - Active analysts") {
    CaseManager mgr;

    CaseInfo info1;
    info1.title = "Case 1";
    std::string id1 = mgr.createCase(info1);
    mgr.assignCase(id1, "analyst-01");

    CaseInfo info2;
    info2.title = "Case 2";
    std::string id2 = mgr.createCase(info2);
    mgr.assignCase(id2, "analyst-01");

    CaseInfo info3;
    info3.title = "Case 3";
    std::string id3 = mgr.createCase(info3);
    mgr.assignCase(id3, "analyst-02");

    auto analysts = mgr.getActiveAnalysts();
    CHECK(analysts.size() == 2);
}

TEST_CASE("CaseManager - Case count") {
    CaseManager mgr;
    CHECK(mgr.getCaseCount() == 0);

    CaseInfo info;
    info.title = "Test";
    mgr.createCase(info);
    CHECK(mgr.getCaseCount() == 1);
}
