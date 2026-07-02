#include <doctest/doctest.h>
#include <soc/SOCDashboardData.h>
#include <string>
#include <vector>

using namespace ThreatOne::SOC;

TEST_CASE("SOCDashboardData - Compute metrics") {
    SOCDashboardData dashboard;

    std::vector<CaseInfo> cases;
    CaseInfo c1;
    c1.status = CaseStatus::Open;
    c1.assignee = "analyst-01";
    cases.push_back(c1);

    CaseInfo c2;
    c2.status = CaseStatus::Closed;
    c2.assignee = "analyst-01";
    cases.push_back(c2);

    CaseInfo c3;
    c3.status = CaseStatus::Investigating;
    c3.assignee = "analyst-02";
    cases.push_back(c3);

    std::vector<std::string> analysts = {"analyst-01", "analyst-02"};

    auto metrics = dashboard.computeMetrics(cases, analysts);
    CHECK(metrics.openCases == 2);
    CHECK(metrics.closedCases == 1);
    CHECK(metrics.activeAnalysts == 2);
}

TEST_CASE("SOCDashboardData - Record and get KPIs") {
    SOCDashboardData dashboard;

    dashboard.recordDetectionTime(10.0);
    dashboard.recordDetectionTime(20.0);
    dashboard.recordResponseTime(30.0);
    dashboard.recordResponseTime(50.0);
    dashboard.recordContainmentTime(60.0);
    dashboard.recordResolutionTime(120.0);

    auto kpis = dashboard.getKPIs();
    CHECK(kpis.meanTimeToDetect == doctest::Approx(15.0));
    CHECK(kpis.meanTimeToRespond == doctest::Approx(40.0));
    CHECK(kpis.meanTimeToContain == doctest::Approx(60.0));
    CHECK(kpis.meanTimeToResolve == doctest::Approx(120.0));
}

TEST_CASE("SOCDashboardData - Alert tracking") {
    SOCDashboardData dashboard;

    dashboard.recordAlert();
    dashboard.recordAlert();
    dashboard.recordAlert();
    dashboard.recordFalsePositive();

    CHECK(dashboard.getTotalAlerts() == 3);
    CHECK(dashboard.getFalsePositives() == 1);
}

TEST_CASE("SOCDashboardData - Compute workload") {
    SOCDashboardData dashboard;

    std::vector<CaseInfo> cases;
    CaseInfo c1;
    c1.assignee = "analyst-01";
    c1.status = CaseStatus::Open;
    cases.push_back(c1);

    CaseInfo c2;
    c2.assignee = "analyst-01";
    c2.status = CaseStatus::Closed;
    cases.push_back(c2);

    CaseInfo c3;
    c3.assignee = "analyst-02";
    c3.status = CaseStatus::Open;
    cases.push_back(c3);

    auto workload = dashboard.computeWorkload(cases);
    CHECK(workload.size() == 2);
}

TEST_CASE("SOCDashboardData - SLA compliance calculation") {
    SOCDashboardData dashboard;

    dashboard.recordAlert();
    dashboard.recordAlert();
    dashboard.recordAlert();
    dashboard.recordAlert();
    dashboard.recordFalsePositive();

    auto kpis = dashboard.getKPIs();
    CHECK(kpis.slaCompliance == doctest::Approx(0.75));
}
