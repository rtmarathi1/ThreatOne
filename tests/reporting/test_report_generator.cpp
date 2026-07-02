#include <doctest/doctest.h>
#include <reporting/ReportGenerator.h>
#include <string>

using namespace ThreatOne::Reporting;

TEST_CASE("ReportGenerator - generate basic report") {
    ReportGenerator generator;

    ReportConfig config;
    config.title = "Security Assessment Q4";
    config.type = ReportType::Executive;
    config.detailLevel = DetailLevel::Standard;
    config.author = "Security Team";

    auto result = generator.generateReport(config);
    REQUIRE(result.isOk());

    auto report = result.value();
    CHECK_FALSE(report.id.empty());
    CHECK(report.title == "Security Assessment Q4");
    CHECK(report.type == ReportType::Executive);
    CHECK(report.detailLevel == DetailLevel::Standard);
    CHECK(report.author == "Security Team");
    CHECK_FALSE(report.generatedAt.empty());
    CHECK_FALSE(report.content.empty());
    CHECK(report.sizeBytes > 0);
}

TEST_CASE("ReportGenerator - generate all report types") {
    ReportGenerator generator;

    SUBCASE("Executive report") {
        ReportConfig config;
        config.title = "Executive Summary";
        config.type = ReportType::Executive;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().type == ReportType::Executive);
        CHECK(result.value().content.find("Executive") != std::string::npos);
    }

    SUBCASE("Technical report") {
        ReportConfig config;
        config.title = "Technical Analysis";
        config.type = ReportType::Technical;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().type == ReportType::Technical);
        CHECK(result.value().content.find("Technical") != std::string::npos);
    }

    SUBCASE("Incident report") {
        ReportConfig config;
        config.title = "Incident Response";
        config.type = ReportType::Incident;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().type == ReportType::Incident);
    }

    SUBCASE("Compliance report") {
        ReportConfig config;
        config.title = "Compliance Status";
        config.type = ReportType::Compliance;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().type == ReportType::Compliance);
    }

    SUBCASE("Vulnerability report") {
        ReportConfig config;
        config.title = "Vulnerability Scan Results";
        config.type = ReportType::Vulnerability;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().type == ReportType::Vulnerability);
    }

    SUBCASE("Scan report") {
        ReportConfig config;
        config.title = "Full System Scan";
        config.type = ReportType::Scan;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().type == ReportType::Scan);
    }

    SUBCASE("Audit report") {
        ReportConfig config;
        config.title = "Security Audit";
        config.type = ReportType::Audit;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().type == ReportType::Audit);
    }

    SUBCASE("Risk report") {
        ReportConfig config;
        config.title = "Risk Assessment";
        config.type = ReportType::Risk;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().type == ReportType::Risk);
    }
}

TEST_CASE("ReportGenerator - configurable sections") {
    ReportGenerator generator;

    ReportConfig config;
    config.title = "Sectioned Report";
    config.type = ReportType::Technical;

    ReportSection s1;
    s1.id = "overview";
    s1.title = "Overview";
    s1.content = "This is the overview section";
    s1.order = 1;
    s1.enabled = true;

    ReportSection s2;
    s2.id = "findings";
    s2.title = "Findings";
    s2.content = "Critical findings here";
    s2.order = 2;
    s2.enabled = true;

    ReportSection s3;
    s3.id = "disabled";
    s3.title = "Disabled Section";
    s3.content = "This should not appear";
    s3.order = 3;
    s3.enabled = false;

    config.sections = {s1, s2, s3};

    auto result = generator.generateReport(config);
    REQUIRE(result.isOk());

    auto report = result.value();
    CHECK(report.sections.size() == 3);
    CHECK(report.content.find("Overview") != std::string::npos);
    CHECK(report.content.find("Critical findings here") != std::string::npos);
    // Disabled sections are not included in generated content
    CHECK(report.content.find("This should not appear") == std::string::npos);
}

TEST_CASE("ReportGenerator - detail levels") {
    ReportGenerator generator;

    SUBCASE("Summary level") {
        ReportConfig config;
        config.title = "Summary Report";
        config.type = ReportType::Executive;
        config.detailLevel = DetailLevel::Summary;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().content.find("Summary") != std::string::npos);
    }

    SUBCASE("Full level") {
        ReportConfig config;
        config.title = "Full Report";
        config.type = ReportType::Technical;
        config.detailLevel = DetailLevel::Full;
        auto result = generator.generateReport(config);
        REQUIRE(result.isOk());
        CHECK(result.value().content.find("Full") != std::string::npos);
    }
}

TEST_CASE("ReportGenerator - empty title returns error") {
    ReportGenerator generator;

    ReportConfig config;
    config.title = "";
    config.type = ReportType::Executive;

    auto result = generator.generateReport(config);
    REQUIRE(result.isErr());
    CHECK(result.error().category() == ThreatOne::Core::ErrorCategory::Validation);
}

TEST_CASE("ReportGenerator - unique IDs for each report") {
    ReportGenerator generator;

    ReportConfig config1;
    config1.title = "Report 1";
    ReportConfig config2;
    config2.title = "Report 2";

    auto r1 = generator.generateReport(config1);
    auto r2 = generator.generateReport(config2);

    REQUIRE(r1.isOk());
    REQUIRE(r2.isOk());
    CHECK(r1.value().id != r2.value().id);
}

TEST_CASE("ReportGenerator - get reports") {
    ReportGenerator generator;

    CHECK(generator.getReportCount() == 0);

    ReportConfig config;
    config.title = "Test Report";
    generator.generateReport(config);

    CHECK(generator.getReportCount() == 1);
    auto reports = generator.getReports();
    CHECK(reports.size() == 1);
    CHECK(reports[0].title == "Test Report");
}

TEST_CASE("ReportGenerator - get report by ID") {
    ReportGenerator generator;

    ReportConfig config;
    config.title = "Find Me";
    auto result = generator.generateReport(config);
    REQUIRE(result.isOk());

    auto found = generator.getReport(result.value().id);
    REQUIRE(found.has_value());
    CHECK(found->title == "Find Me");

    auto notFound = generator.getReport("nonexistent");
    CHECK_FALSE(notFound.has_value());
}

TEST_CASE("ReportGenerator - metadata in report") {
    ReportGenerator generator;

    ReportConfig config;
    config.title = "Metadata Report";
    config.metadata["severity"] = "high";
    config.metadata["scope"] = "network";

    auto result = generator.generateReport(config);
    REQUIRE(result.isOk());
    CHECK(result.value().metadata["severity"] == "high");
    CHECK(result.value().metadata["scope"] == "network");
    CHECK(result.value().content.find("severity") != std::string::npos);
}
