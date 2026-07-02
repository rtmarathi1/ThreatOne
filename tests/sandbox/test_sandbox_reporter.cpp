#include <doctest/doctest.h>
#include <sandbox/SandboxEngine.h>

using namespace ThreatOne::Sandbox;

TEST_CASE("SandboxReporter - Generate text report") {
    SandboxEngine engine;
    auto& sr = engine.getSandboxReporter();

    AnalysisResult analysis;
    analysis.id = "SAMPLE-1";
    analysis.verdict = "malicious";
    analysis.score = 90.0;
    analysis.sampleHash = "sha256:abc123";

    BehaviorReport behaviors;
    behaviors.sampleId = "SAMPLE-1";
    behaviors.processesCreated = {"cmd.exe"};

    std::vector<IOCInfo> iocs;
    IOCInfo ioc;
    ioc.type = "ip";
    ioc.value = "10.0.0.1";
    ioc.confidence = "high";
    iocs.push_back(ioc);

    auto reportId = sr.generateReport("SAMPLE-1", analysis, behaviors, iocs, ReportFormat::Text);
    CHECK_FALSE(reportId.empty());

    auto report = sr.getReport(reportId);
    REQUIRE(report.has_value());
    CHECK(report->sampleId == "SAMPLE-1");
    CHECK(report->verdict == SandboxVerdict::Malicious);
    CHECK_FALSE(report->content.empty());
    CHECK_FALSE(report->recommendations.empty());
}

TEST_CASE("SandboxReporter - Generate JSON report") {
    SandboxEngine engine;
    auto& sr = engine.getSandboxReporter();

    AnalysisResult analysis;
    analysis.id = "SAMPLE-1";
    analysis.verdict = "suspicious";
    analysis.score = 50.0;

    BehaviorReport behaviors;
    behaviors.sampleId = "SAMPLE-1";

    auto reportId = sr.generateReport("SAMPLE-1", analysis, behaviors, {}, ReportFormat::JSON);
    auto report = sr.getReport(reportId);
    REQUIRE(report.has_value());
    CHECK(report->content.find("verdict") != std::string::npos);
}

TEST_CASE("SandboxReporter - Generate summary report") {
    SandboxEngine engine;
    auto& sr = engine.getSandboxReporter();

    AnalysisResult analysis;
    analysis.id = "SAMPLE-1";
    analysis.verdict = "clean";
    analysis.score = 0.0;

    auto reportId = sr.generateSummaryReport("SAMPLE-1", analysis);
    auto report = sr.getReport(reportId);
    REQUIRE(report.has_value());
    CHECK(report->format == ReportFormat::Summary);
}

TEST_CASE("SandboxReporter - Template CRUD") {
    SandboxEngine engine;
    auto& sr = engine.getSandboxReporter();

    ReportTemplate tmpl;
    tmpl.name = "Executive Summary";
    tmpl.format = ReportFormat::Text;
    tmpl.includeIOCs = true;
    tmpl.includeRecommendations = true;

    auto id = sr.createTemplate(tmpl);
    CHECK_FALSE(id.empty());

    auto templates = sr.getTemplates();
    CHECK(templates.size() == 1);

    CHECK(sr.deleteTemplate(id));
    CHECK(sr.getTemplates().empty());
}

TEST_CASE("SandboxReporter - Get reports for sample") {
    SandboxEngine engine;
    auto& sr = engine.getSandboxReporter();

    AnalysisResult analysis;
    analysis.id = "SAMPLE-1";
    analysis.verdict = "clean";

    BehaviorReport behaviors;
    behaviors.sampleId = "SAMPLE-1";

    sr.generateReport("SAMPLE-1", analysis, behaviors, {}, ReportFormat::Text);
    sr.generateReport("SAMPLE-1", analysis, behaviors, {}, ReportFormat::JSON);

    auto reports = sr.getReportsForSample("SAMPLE-1");
    CHECK(reports.size() == 2);
}

TEST_CASE("SandboxReporter - Recommendations by verdict") {
    SandboxEngine engine;
    auto& sr = engine.getSandboxReporter();

    auto malRecs = sr.generateRecommendations(SandboxVerdict::Malicious, {});
    CHECK(malRecs.size() >= 3);

    auto cleanRecs = sr.generateRecommendations(SandboxVerdict::Clean, {});
    CHECK_FALSE(cleanRecs.empty());
}

TEST_CASE("SandboxReporter - Statistics") {
    SandboxEngine engine;
    auto& sr = engine.getSandboxReporter();

    CHECK(sr.getTotalReportsGenerated() == 0);

    AnalysisResult analysis;
    analysis.id = "S1";
    analysis.verdict = "clean";
    BehaviorReport b;
    sr.generateReport("S1", analysis, b, {});

    CHECK(sr.getTotalReportsGenerated() == 1);
    CHECK(sr.getReportCount() == 1);
}
