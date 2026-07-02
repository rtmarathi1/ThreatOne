#include <doctest/doctest.h>
#include <compliance/ComplianceScanner.h>
#include <compliance/ComplianceFramework.h>
#include <string>

using namespace ThreatOne::Compliance;

TEST_CASE("ComplianceScanner - scan framework produces findings") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);

    SystemState state;
    auto result = scanner.scan(Framework::NIST, state);
    REQUIRE(result.isOk());

    auto findings = result.value();
    CHECK(findings.size() == 25); // 5 categories * 5 controls
    CHECK(scanner.getScanCount() == 1);
}

TEST_CASE("ComplianceScanner - findings have all statuses") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);

    SystemState state;
    // Set up some controls as pass, some as fail, some as not applicable
    state.configurations["NIST-ID-1.status"] = "pass";
    state.configurations["NIST-ID-2.status"] = "fail";
    state.configurations["NIST-ID-3.status"] = "warning";
    state.configurations["NIST-ID-4.not_applicable"] = "true";

    auto result = scanner.scan(Framework::NIST, state);
    REQUIRE(result.isOk());

    auto findings = result.value();

    // Verify different statuses exist
    bool hasPass = false, hasFail = false, hasWarning = false, hasNA = false;
    for (const auto& f : findings) {
        if (f.status == FindingStatus::Pass) hasPass = true;
        if (f.status == FindingStatus::Fail) hasFail = true;
        if (f.status == FindingStatus::Warning) hasWarning = true;
        if (f.status == FindingStatus::NotApplicable) hasNA = true;
    }
    CHECK(hasPass);
    CHECK(hasFail);
    CHECK(hasWarning);
    CHECK(hasNA);
}

TEST_CASE("ComplianceScanner - scan with enabled features") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);

    SystemState state;
    state.enabledFeatures.push_back("NIST-ID");
    state.installedPolicies.push_back("NIST-ID");

    auto result = scanner.scan(Framework::NIST, state);
    REQUIRE(result.isOk());

    // Controls in NIST-ID category should pass
    auto findings = result.value();
    for (const auto& f : findings) {
        if (f.controlId.find("NIST-ID") != std::string::npos) {
            CHECK(f.status == FindingStatus::Pass);
        }
    }
}

TEST_CASE("ComplianceScanner - scan control individually") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);

    ControlInfo ctrl;
    ctrl.id = "TEST-1";
    ctrl.name = "Test Control";
    ctrl.description = "A test control";
    ctrl.framework = Framework::NIST;
    ctrl.categoryId = "TEST";
    ctrl.implemented = false;

    SystemState state;
    state.configurations["TEST-1.status"] = "pass";

    auto finding = scanner.scanControl(ctrl, state);
    CHECK(finding.status == FindingStatus::Pass);
    CHECK(finding.controlId == "TEST-1");
    CHECK(finding.framework == Framework::NIST);
    CHECK_FALSE(finding.id.empty());
    CHECK_FALSE(finding.timestamp.empty());
}

TEST_CASE("ComplianceScanner - get findings by status") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);

    SystemState state;
    state.configurations["NIST-ID-1.status"] = "pass";
    state.configurations["NIST-ID-2.status"] = "fail";

    scanner.scan(Framework::NIST, state);

    auto passFindings = scanner.getFindingsByStatus(FindingStatus::Pass);
    CHECK_FALSE(passFindings.empty());
    for (const auto& f : passFindings) {
        CHECK(f.status == FindingStatus::Pass);
    }

    auto failFindings = scanner.getFindingsByStatus(FindingStatus::Fail);
    CHECK_FALSE(failFindings.empty());
    for (const auto& f : failFindings) {
        CHECK(f.status == FindingStatus::Fail);
    }
}

TEST_CASE("ComplianceScanner - get findings by framework") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);

    SystemState state;
    scanner.scan(Framework::NIST, state);

    auto nistFindings = scanner.getFindingsByFramework(Framework::NIST);
    CHECK(nistFindings.size() == 25);

    auto isoFindings = scanner.getFindingsByFramework(Framework::ISO27001);
    CHECK(isoFindings.empty());
}

TEST_CASE("ComplianceScanner - clear findings") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);

    SystemState state;
    scanner.scan(Framework::NIST, state);
    CHECK_FALSE(scanner.getFindings().empty());

    scanner.clearFindings();
    CHECK(scanner.getFindings().empty());
}

TEST_CASE("ComplianceScanner - multiple scans accumulate findings") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);

    SystemState state;
    scanner.scan(Framework::NIST, state);
    scanner.scan(Framework::SOC2, state);

    CHECK(scanner.getScanCount() == 2);
    auto allFindings = scanner.getFindings();
    CHECK(allFindings.size() > 25); // More than one framework scanned
}
