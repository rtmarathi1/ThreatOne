#include <doctest/doctest.h>
#include <reporting/ReportTemplate.h>
#include <map>
#include <string>
#include <vector>

using namespace ThreatOne::Reporting;

TEST_CASE("ReportTemplateEngine - create template") {
    ReportTemplateEngine engine;

    ReportTemplate tmpl;
    tmpl.name = "Corporate Standard";
    tmpl.header = "=== {company_name} Security Report ===";
    tmpl.footer = "--- Confidential - {company_name} ---";
    tmpl.companyName = "ThreatOne Inc";

    auto result = engine.createTemplate(tmpl);
    REQUIRE(result.isOk());
    CHECK_FALSE(result.value().empty());
}

TEST_CASE("ReportTemplateEngine - empty name returns error") {
    ReportTemplateEngine engine;

    ReportTemplate tmpl;
    tmpl.name = "";

    auto result = engine.createTemplate(tmpl);
    REQUIRE(result.isErr());
    CHECK(result.error().category() == ThreatOne::Core::ErrorCategory::Validation);
}

TEST_CASE("ReportTemplateEngine - placeholder substitution") {
    SUBCASE("Basic placeholder replacement") {
        std::map<std::string, std::string> vars;
        vars["company_name"] = "AcmeCorp";
        vars["date"] = "2024-01-15";
        vars["title"] = "Monthly Report";

        std::string content = "Report for {company_name} generated on {date}: {title}";
        auto result = ReportTemplateEngine::renderSection(content, vars);

        CHECK(result == "Report for AcmeCorp generated on 2024-01-15: Monthly Report");
    }

    SUBCASE("Multiple occurrences of same placeholder") {
        std::map<std::string, std::string> vars;
        vars["name"] = "TestCo";

        std::string content = "{name} - Report by {name}";
        auto result = ReportTemplateEngine::renderSection(content, vars);
        CHECK(result == "TestCo - Report by TestCo");
    }

    SUBCASE("No placeholders in content") {
        std::map<std::string, std::string> vars;
        vars["unused"] = "value";

        std::string content = "No placeholders here";
        auto result = ReportTemplateEngine::renderSection(content, vars);
        CHECK(result == "No placeholders here");
    }

    SUBCASE("Unmatched placeholder left as-is") {
        std::map<std::string, std::string> vars;
        vars["name"] = "TestCo";

        std::string content = "{name} has {unknown} placeholder";
        auto result = ReportTemplateEngine::renderSection(content, vars);
        CHECK(result == "TestCo has {unknown} placeholder");
    }
}

TEST_CASE("ReportTemplateEngine - render template with header/footer") {
    ReportTemplateEngine engine;

    ReportTemplate tmpl;
    tmpl.name = "Test Template";
    tmpl.header = "Header: {company_name}";
    tmpl.footer = "Footer: {date}";
    tmpl.companyName = "SecurityCo";

    TemplateSection sec;
    sec.id = "main";
    sec.name = "Main";
    sec.templateContent = "Content for {company_name}";
    sec.order = 1;
    tmpl.sections = {sec};

    auto createResult = engine.createTemplate(tmpl);
    REQUIRE(createResult.isOk());

    std::map<std::string, std::string> vars;
    vars["date"] = "2024-03-01";

    auto rendered = engine.renderTemplate(createResult.value(), vars);
    CHECK(rendered.find("Header: SecurityCo") != std::string::npos);
    CHECK(rendered.find("Content for SecurityCo") != std::string::npos);
    CHECK(rendered.find("Footer: 2024-03-01") != std::string::npos);
}

TEST_CASE("ReportTemplateEngine - section assembly") {
    ReportTemplateEngine engine;

    ReportTemplate tmpl;
    tmpl.name = "Assembly Template";
    tmpl.header = "=== Report Start ===";
    tmpl.footer = "=== Report End ===";

    auto createResult = engine.createTemplate(tmpl);
    REQUIRE(createResult.isOk());

    std::vector<ReportSection> sections;
    ReportSection s1;
    s1.id = "s1";
    s1.title = "Introduction";
    s1.content = "Welcome to the report";
    s1.order = 1;
    s1.enabled = true;

    ReportSection s2;
    s2.id = "s2";
    s2.title = "Analysis";
    s2.content = "Detailed analysis";
    s2.order = 2;
    s2.enabled = true;

    ReportSection s3;
    s3.id = "s3";
    s3.title = "Disabled";
    s3.content = "Should not appear";
    s3.order = 3;
    s3.enabled = false;

    sections = {s2, s1, s3}; // out of order

    auto assembled = engine.assembleSections(createResult.value(), sections);
    CHECK(assembled.find("=== Report Start ===") != std::string::npos);
    CHECK(assembled.find("=== Report End ===") != std::string::npos);
    CHECK(assembled.find("Introduction") != std::string::npos);
    CHECK(assembled.find("Detailed analysis") != std::string::npos);
    CHECK(assembled.find("Should not appear") == std::string::npos);

    // Verify order: Introduction before Analysis
    auto introPos = assembled.find("Introduction");
    auto analysisPos = assembled.find("Analysis");
    CHECK(introPos < analysisPos);
}

TEST_CASE("ReportTemplateEngine - get and delete templates") {
    ReportTemplateEngine engine;

    CHECK(engine.getTemplateCount() == 0);

    ReportTemplate tmpl;
    tmpl.name = "Template A";
    auto r1 = engine.createTemplate(tmpl);
    REQUIRE(r1.isOk());

    tmpl.name = "Template B";
    auto r2 = engine.createTemplate(tmpl);
    REQUIRE(r2.isOk());

    CHECK(engine.getTemplateCount() == 2);
    CHECK(engine.getTemplates().size() == 2);

    auto retrieved = engine.getTemplate(r1.value());
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Template A");

    CHECK(engine.deleteTemplate(r1.value()));
    CHECK(engine.getTemplateCount() == 1);
    CHECK_FALSE(engine.getTemplate(r1.value()).has_value());

    CHECK_FALSE(engine.deleteTemplate("nonexistent"));
}

TEST_CASE("ReportTemplateEngine - render nonexistent template returns empty") {
    ReportTemplateEngine engine;

    std::map<std::string, std::string> vars;
    auto result = engine.renderTemplate("no-such-id", vars);
    CHECK(result.empty());
}
