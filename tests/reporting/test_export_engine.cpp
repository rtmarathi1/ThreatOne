#include <doctest/doctest.h>
#include <reporting/ExportEngine.h>

#include <nlohmann/json.hpp>

using namespace ThreatOne::Reporting;

static Report makeTestReport() {
    Report report;
    report.id = "rpt-test-001";
    report.title = "Test Security Report";
    report.type = ReportType::Technical;
    report.detailLevel = DetailLevel::Standard;
    report.content = "Test report content here";
    report.generatedAt = "2024-01-15 10:00:00";
    report.author = "TestAuthor";
    report.sizeBytes = 100;

    ReportSection s1;
    s1.id = "s1";
    s1.title = "Overview";
    s1.content = "Security overview data";
    s1.order = 1;
    s1.enabled = true;

    ReportSection s2;
    s2.id = "s2";
    s2.title = "Findings";
    s2.content = "Critical vulnerabilities found";
    s2.order = 2;
    s2.enabled = true;

    report.sections = {s1, s2};
    report.metadata["severity"] = "high";
    return report;
}

TEST_CASE("ExportEngine - export to PDF") {
    ExportEngine engine;
    auto report = makeTestReport();

    auto result = engine.exportToPDF(report);
    REQUIRE(result.isOk());

    auto pdf = result.value();
    CHECK(pdf.find("%PDF-1.4") != std::string::npos);
    CHECK(pdf.find("Test Security Report") != std::string::npos);
    CHECK(pdf.find("Technical") != std::string::npos);
    CHECK(pdf.find("[HEADER] Overview") != std::string::npos);
    CHECK(pdf.find("[HEADER] Findings") != std::string::npos);
    CHECK(pdf.find("%%EOF") != std::string::npos);
}

TEST_CASE("ExportEngine - export to HTML") {
    ExportEngine engine;
    auto report = makeTestReport();

    auto result = engine.exportToHTML(report);
    REQUIRE(result.isOk());

    auto html = result.value();
    CHECK(html.find("<!DOCTYPE html>") != std::string::npos);
    CHECK(html.find("<title>Test Security Report</title>") != std::string::npos);
    CHECK(html.find("<h1>Test Security Report</h1>") != std::string::npos);
    CHECK(html.find("TestAuthor") != std::string::npos);
    CHECK(html.find("Overview") != std::string::npos);
    CHECK(html.find("Security overview data") != std::string::npos);
    CHECK(html.find("</html>") != std::string::npos);
    // CSS should be present
    CHECK(html.find("<style>") != std::string::npos);
}

TEST_CASE("ExportEngine - HTML escapes special characters") {
    ExportEngine engine;

    Report report;
    report.id = "rpt-escape";
    report.title = "Report <with> & \"special\" chars";
    report.type = ReportType::Technical;
    report.content = "";
    report.generatedAt = "2024-01-01";
    report.author = "Author";

    auto result = engine.exportToHTML(report);
    REQUIRE(result.isOk());

    auto html = result.value();
    CHECK(html.find("&lt;with&gt;") != std::string::npos);
    CHECK(html.find("&amp;") != std::string::npos);
    CHECK(html.find("&quot;special&quot;") != std::string::npos);
}

TEST_CASE("ExportEngine - export to JSON") {
    ExportEngine engine;
    auto report = makeTestReport();

    auto result = engine.exportToJSON(report);
    REQUIRE(result.isOk());

    auto j = nlohmann::json::parse(result.value());
    CHECK(j["id"] == "rpt-test-001");
    CHECK(j["title"] == "Test Security Report");
    CHECK(j["type"] == "Technical");
    CHECK(j["detailLevel"] == "Standard");
    CHECK(j["author"] == "TestAuthor");
    CHECK(j["sizeBytes"] == 100);
    CHECK(j["sections"].size() == 2);
    CHECK(j["sections"][0]["title"] == "Overview");
    CHECK(j["sections"][1]["title"] == "Findings");
    CHECK(j["metadata"]["severity"] == "high");
}

TEST_CASE("ExportEngine - export to CSV") {
    ExportEngine engine;
    auto report = makeTestReport();

    auto result = engine.exportToCSV(report);
    REQUIRE(result.isOk());

    auto csv = result.value();
    // Check header
    CHECK(csv.find("Section ID,Section Title,Content,Order,Enabled") != std::string::npos);
    // Check data rows
    CHECK(csv.find("s1") != std::string::npos);
    CHECK(csv.find("Overview") != std::string::npos);
    CHECK(csv.find("s2") != std::string::npos);
    CHECK(csv.find("Findings") != std::string::npos);
}

TEST_CASE("ExportEngine - CSV escapes commas and quotes") {
    ExportEngine engine;

    Report report;
    report.id = "rpt-csv";
    report.title = "CSV Test";
    report.type = ReportType::Scan;
    report.content = "";
    report.generatedAt = "2024-01-01";
    report.author = "Author";

    ReportSection s;
    s.id = "s1";
    s.title = "Section with, comma";
    s.content = "Content with \"quotes\"";
    s.order = 1;
    s.enabled = true;
    report.sections = {s};

    auto result = engine.exportToCSV(report);
    REQUIRE(result.isOk());

    auto csv = result.value();
    // Commas and quotes should be escaped
    CHECK(csv.find("\"Section with, comma\"") != std::string::npos);
    CHECK(csv.find("\"Content with \"\"quotes\"\"\"") != std::string::npos);
}

TEST_CASE("ExportEngine - dispatch by format") {
    ExportEngine engine;
    auto report = makeTestReport();

    SUBCASE("PDF format") {
        auto result = engine.exportReport(report, ExportFormat::PDF);
        REQUIRE(result.isOk());
        CHECK(result.value().find("%PDF") != std::string::npos);
    }

    SUBCASE("HTML format") {
        auto result = engine.exportReport(report, ExportFormat::HTML);
        REQUIRE(result.isOk());
        CHECK(result.value().find("<!DOCTYPE html>") != std::string::npos);
    }

    SUBCASE("JSON format") {
        auto result = engine.exportReport(report, ExportFormat::JSON);
        REQUIRE(result.isOk());
        auto j = nlohmann::json::parse(result.value());
        CHECK(j["id"] == "rpt-test-001");
    }

    SUBCASE("CSV format") {
        auto result = engine.exportReport(report, ExportFormat::CSV);
        REQUIRE(result.isOk());
        CHECK(result.value().find("Section ID") != std::string::npos);
    }
}

TEST_CASE("ExportEngine - report without sections") {
    ExportEngine engine;

    Report report;
    report.id = "rpt-nosections";
    report.title = "No Sections Report";
    report.type = ReportType::Executive;
    report.content = "Just content, no sections";
    report.generatedAt = "2024-02-01";
    report.author = "Admin";
    report.sizeBytes = 50;

    SUBCASE("PDF with no sections shows content") {
        auto result = engine.exportToPDF(report);
        REQUIRE(result.isOk());
        CHECK(result.value().find("Just content, no sections") != std::string::npos);
    }

    SUBCASE("HTML with no sections shows content") {
        auto result = engine.exportToHTML(report);
        REQUIRE(result.isOk());
        CHECK(result.value().find("Just content, no sections") != std::string::npos);
    }

    SUBCASE("CSV with no sections exports as single row") {
        auto result = engine.exportToCSV(report);
        REQUIRE(result.isOk());
        CHECK(result.value().find("No Sections Report") != std::string::npos);
    }
}
