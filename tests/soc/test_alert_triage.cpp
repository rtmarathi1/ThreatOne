#include <doctest/doctest.h>
#include <soc/AlertTriage.h>
#include <string>

using namespace ThreatOne::SOC;

TEST_CASE("AlertTriage - Ingest alert") {
    AlertTriage triage;

    TriageAlert alert;
    alert.title = "Suspicious Connection";
    alert.source = "firewall";
    alert.severity = AlertSeverity::High;

    std::string id = triage.ingestAlert(alert);
    CHECK_FALSE(id.empty());
    CHECK(id.find("ALR-") == 0);
}

TEST_CASE("AlertTriage - Triage alert") {
    AlertTriage triage;

    TriageAlert alert;
    alert.title = "Test Alert";
    alert.severity = AlertSeverity::Medium;
    std::string id = triage.ingestAlert(alert);

    CHECK(triage.triageAlert(id));
    auto fetched = triage.getAlert(id);
    CHECK(fetched.status == AlertStatus::Triaged);

    CHECK_FALSE(triage.triageAlert("nonexistent"));
}

TEST_CASE("AlertTriage - Assign alert") {
    AlertTriage triage;

    TriageAlert alert;
    alert.title = "Assign Test";
    alert.severity = AlertSeverity::High;
    std::string id = triage.ingestAlert(alert);

    CHECK(triage.assignAlert(id, "analyst-01"));
    auto fetched = triage.getAlert(id);
    CHECK(fetched.assignedTo == "analyst-01");
    CHECK(fetched.status == AlertStatus::Assigned);

    CHECK_FALSE(triage.assignAlert("nonexistent", "analyst"));
}

TEST_CASE("AlertTriage - Dismiss alert") {
    AlertTriage triage;

    TriageAlert alert;
    alert.title = "False positive";
    alert.severity = AlertSeverity::Low;
    std::string id = triage.ingestAlert(alert);

    CHECK(triage.dismissAlert(id, "False positive"));
    auto fetched = triage.getAlert(id);
    CHECK(fetched.status == AlertStatus::Dismissed);

    CHECK_FALSE(triage.dismissAlert("nonexistent", "reason"));
}

TEST_CASE("AlertTriage - Resolve alert") {
    AlertTriage triage;

    TriageAlert alert;
    alert.title = "Resolved test";
    alert.severity = AlertSeverity::Medium;
    std::string id = triage.ingestAlert(alert);

    CHECK(triage.resolveAlert(id));
    CHECK_FALSE(triage.resolveAlert("nonexistent"));
}

TEST_CASE("AlertTriage - Get alerts by status") {
    AlertTriage triage;

    TriageAlert a1;
    a1.title = "Alert 1";
    a1.severity = AlertSeverity::High;
    std::string id1 = triage.ingestAlert(a1);

    TriageAlert a2;
    a2.title = "Alert 2";
    a2.severity = AlertSeverity::Low;
    std::string id2 = triage.ingestAlert(a2);

    triage.triageAlert(id1);

    auto newAlerts = triage.getAlertsByStatus(AlertStatus::New);
    CHECK(newAlerts.size() == 1);

    auto triaged = triage.getAlertsByStatus(AlertStatus::Triaged);
    CHECK(triaged.size() == 1);
}

TEST_CASE("AlertTriage - Get alerts by severity") {
    AlertTriage triage;

    TriageAlert a1;
    a1.title = "Critical 1";
    a1.severity = AlertSeverity::Critical;
    triage.ingestAlert(a1);

    TriageAlert a2;
    a2.title = "Low 1";
    a2.severity = AlertSeverity::Low;
    triage.ingestAlert(a2);

    auto critical = triage.getAlertsBySeverity(AlertSeverity::Critical);
    CHECK(critical.size() == 1);
}

TEST_CASE("AlertTriage - Alert queue") {
    AlertTriage triage;

    TriageAlert a1;
    a1.title = "Alert 1";
    a1.severity = AlertSeverity::High;
    triage.ingestAlert(a1);

    TriageAlert a2;
    a2.title = "Alert 2";
    a2.severity = AlertSeverity::Critical;
    triage.ingestAlert(a2);

    auto queue = triage.getAlertQueue();
    CHECK(queue.size() == 2);
}

TEST_CASE("AlertTriage - Add and remove triage rules") {
    AlertTriage triage;

    TriageRule rule;
    rule.name = "Critical Boost";
    rule.condition = "severity=critical";
    rule.scoreModifier = 10.0;

    std::string id = triage.addTriageRule(rule);
    CHECK_FALSE(id.empty());
    CHECK(id.find("TR-") == 0);

    auto rules = triage.getTriageRules();
    CHECK(rules.size() == 1);

    CHECK(triage.removeTriageRule(id));
    CHECK_FALSE(triage.removeTriageRule("nonexistent"));
}

TEST_CASE("AlertTriage - Find duplicate") {
    AlertTriage triage;

    TriageAlert a1;
    a1.title = "Brute Force";
    a1.source = "auth-service";
    a1.severity = AlertSeverity::High;
    std::string id1 = triage.ingestAlert(a1);

    TriageAlert a2;
    a2.title = "Brute Force";
    a2.source = "auth-service";
    a2.severity = AlertSeverity::High;

    std::string dup = triage.findDuplicate(a2);
    CHECK(dup == id1);

    TriageAlert a3;
    a3.title = "Different Alert";
    a3.source = "other";
    CHECK(triage.findDuplicate(a3).empty());
}

TEST_CASE("AlertTriage - Group alerts") {
    AlertTriage triage;

    TriageAlert a1;
    a1.title = "Alert A";
    a1.severity = AlertSeverity::Medium;
    std::string id1 = triage.ingestAlert(a1);

    TriageAlert a2;
    a2.title = "Alert B";
    a2.severity = AlertSeverity::Medium;
    std::string id2 = triage.ingestAlert(a2);

    CHECK(triage.groupAlerts(id1, id2));
    auto fetched1 = triage.getAlert(id1);
    auto fetched2 = triage.getAlert(id2);
    CHECK(fetched1.groupId == fetched2.groupId);

    CHECK_FALSE(triage.groupAlerts("nonexistent", id2));
}

TEST_CASE("AlertTriage - Score computation") {
    AlertTriage triage;

    TriageAlert alert;
    alert.title = "Scored Alert";
    alert.severity = AlertSeverity::Critical;
    alert.description = "Has description";
    std::string id = triage.ingestAlert(alert);

    auto fetched = triage.getAlert(id);
    CHECK(fetched.score > 90.0);
}

TEST_CASE("AlertTriage - Alert count") {
    AlertTriage triage;
    CHECK(triage.getAlertCount() == 0);

    TriageAlert a;
    a.title = "Test";
    a.severity = AlertSeverity::Low;
    triage.ingestAlert(a);
    CHECK(triage.getAlertCount() == 1);
}

TEST_CASE("AlertTriage - Suggest assignee") {
    AlertTriage triage;

    std::vector<std::string> analysts = {"a1", "a2", "a3"};
    std::vector<CaseInfo> cases;

    CaseInfo c1;
    c1.assignee = "a1";
    c1.status = CaseStatus::Open;
    cases.push_back(c1);

    CaseInfo c2;
    c2.assignee = "a1";
    c2.status = CaseStatus::Open;
    cases.push_back(c2);

    CaseInfo c3;
    c3.assignee = "a2";
    c3.status = CaseStatus::Open;
    cases.push_back(c3);

    std::string suggested = triage.suggestAssignee(analysts, cases);
    CHECK(suggested == "a3");
}
