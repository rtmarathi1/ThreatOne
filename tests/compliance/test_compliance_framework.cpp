#include <doctest/doctest.h>
#include <compliance/ComplianceFramework.h>

using namespace ThreatOne::Compliance;

TEST_CASE("ComplianceFramework - supports all 7 frameworks") {
    ComplianceFramework fw;

    auto infos = fw.getFrameworkInfos();
    CHECK(infos.size() == 7);

    // Verify each framework is present
    auto allFrameworks = fw.getAllFrameworks();
    CHECK(allFrameworks.size() == 7);
}

TEST_CASE("ComplianceFramework - get specific framework") {
    ComplianceFramework fw;

    SUBCASE("NIST framework") {
        auto nist = fw.getFramework(Framework::NIST);
        REQUIRE(nist.has_value());
        CHECK(nist->name == "NIST CSF");
        CHECK(nist->version == "1.1");
        CHECK(nist->categories.size() == 5);
    }

    SUBCASE("ISO 27001 framework") {
        auto iso = fw.getFramework(Framework::ISO27001);
        REQUIRE(iso.has_value());
        CHECK(iso->name == "ISO 27001");
        CHECK(iso->version == "2022");
        CHECK(iso->categories.size() == 6);
    }

    SUBCASE("SOC 2 framework") {
        auto soc2 = fw.getFramework(Framework::SOC2);
        REQUIRE(soc2.has_value());
        CHECK(soc2->name == "SOC 2");
        CHECK(soc2->categories.size() == 7);
    }

    SUBCASE("HIPAA framework") {
        auto hipaa = fw.getFramework(Framework::HIPAA);
        REQUIRE(hipaa.has_value());
        CHECK(hipaa->name == "HIPAA");
        CHECK(hipaa->categories.size() == 5);
    }

    SUBCASE("PCI-DSS framework") {
        auto pci = fw.getFramework(Framework::PCI_DSS);
        REQUIRE(pci.has_value());
        CHECK(pci->name == "PCI-DSS");
        CHECK(pci->categories.size() == 6);
    }

    SUBCASE("GDPR framework") {
        auto gdpr = fw.getFramework(Framework::GDPR);
        REQUIRE(gdpr.has_value());
        CHECK(gdpr->name == "GDPR");
        CHECK(gdpr->categories.size() == 6);
    }

    SUBCASE("CIS framework") {
        auto cis = fw.getFramework(Framework::CIS);
        REQUIRE(cis.has_value());
        CHECK(cis->name == "CIS Benchmarks");
        CHECK(cis->categories.size() == 7);
    }
}

TEST_CASE("ComplianceFramework - get controls") {
    ComplianceFramework fw;

    auto controls = fw.getControls(Framework::NIST);
    CHECK(controls.size() == 25); // 5 categories * 5 controls each
    CHECK(controls[0].framework == Framework::NIST);
    CHECK_FALSE(controls[0].id.empty());
    CHECK_FALSE(controls[0].name.empty());
}

TEST_CASE("ComplianceFramework - get controls by category") {
    ComplianceFramework fw;

    auto controls = fw.getControlsByCategory(Framework::NIST, "NIST-ID");
    CHECK(controls.size() == 5);
    for (const auto& ctrl : controls) {
        CHECK(ctrl.categoryId == "NIST-ID");
    }
}

TEST_CASE("ComplianceFramework - get specific control") {
    ComplianceFramework fw;

    auto ctrl = fw.getControl(Framework::NIST, "NIST-ID-1");
    REQUIRE(ctrl.has_value());
    CHECK(ctrl->id == "NIST-ID-1");
    CHECK(ctrl->framework == Framework::NIST);
    CHECK(ctrl->categoryId == "NIST-ID");

    auto missing = fw.getControl(Framework::NIST, "NONEXISTENT");
    CHECK_FALSE(missing.has_value());
}

TEST_CASE("ComplianceFramework - get categories") {
    ComplianceFramework fw;

    auto categories = fw.getCategories(Framework::SOC2);
    CHECK(categories.size() == 7);
    CHECK_FALSE(categories[0].id.empty());
    CHECK_FALSE(categories[0].name.empty());
}

TEST_CASE("ComplianceFramework - framework to string") {
    CHECK(ComplianceFramework::frameworkToString(Framework::NIST) == "NIST CSF");
    CHECK(ComplianceFramework::frameworkToString(Framework::ISO27001) == "ISO 27001");
    CHECK(ComplianceFramework::frameworkToString(Framework::SOC2) == "SOC 2");
    CHECK(ComplianceFramework::frameworkToString(Framework::HIPAA) == "HIPAA");
    CHECK(ComplianceFramework::frameworkToString(Framework::PCI_DSS) == "PCI-DSS");
    CHECK(ComplianceFramework::frameworkToString(Framework::GDPR) == "GDPR");
    CHECK(ComplianceFramework::frameworkToString(Framework::CIS) == "CIS Benchmarks");
}

TEST_CASE("ComplianceFramework - framework info summary") {
    ComplianceFramework fw;

    auto infos = fw.getFrameworkInfos();
    for (const auto& info : infos) {
        CHECK(info.totalControls > 0);
        CHECK_FALSE(info.name.empty());
        CHECK_FALSE(info.version.empty());
    }
}
