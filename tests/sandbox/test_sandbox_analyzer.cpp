#include <doctest/doctest.h>
#include <sandbox/SandboxEngine.h>

using namespace ThreatOne::Sandbox;

TEST_CASE("SandboxAnalyzer - Default rules loaded") {
    SandboxEngine engine;
    auto& sa = engine.getSandboxAnalyzer();

    auto rules = sa.getAnalysisRules();
    CHECK(rules.size() >= 4);
}

TEST_CASE("SandboxAnalyzer - Add and remove rule") {
    SandboxEngine engine;
    auto& sa = engine.getSandboxAnalyzer();

    AnalysisRule rule;
    rule.name = "Test Rule";
    rule.behaviorPattern = "suspicious";
    rule.severityWeight = 8;

    auto id = sa.addAnalysisRule(rule);
    CHECK_FALSE(id.empty());

    auto retrieved = sa.getRule(id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Test Rule");

    CHECK(sa.removeAnalysisRule(id));
    CHECK_FALSE(sa.getRule(id).has_value());
}

TEST_CASE("SandboxAnalyzer - Compute verdict clean") {
    SandboxEngine engine;
    auto& sa = engine.getSandboxAnalyzer();

    auto verdict = sa.computeVerdict({});
    CHECK(verdict == SandboxVerdict::Clean);
}

TEST_CASE("SandboxAnalyzer - Compute verdict suspicious") {
    SandboxEngine engine;
    auto& sa = engine.getSandboxAnalyzer();

    auto verdict = sa.computeVerdict({"something"});
    CHECK(verdict == SandboxVerdict::Suspicious);
}

TEST_CASE("SandboxAnalyzer - Compute verdict malicious") {
    SandboxEngine engine;
    auto& sa = engine.getSandboxAnalyzer();

    auto verdict = sa.computeVerdict({"a", "b", "c"});
    CHECK(verdict == SandboxVerdict::Malicious);
}

TEST_CASE("SandboxAnalyzer - Analyze behaviors with rule matching") {
    SandboxEngine engine;
    auto& sa = engine.getSandboxAnalyzer();

    std::vector<std::string> behaviors = {
        "created cmd.exe",
        "launched powershell -enc abc",
        "modified registry key"
    };

    auto details = sa.analyzeBehaviors(behaviors);
    CHECK(details.threatScore > 0.0);
    CHECK_FALSE(details.matchedRules.empty());
}

TEST_CASE("SandboxAnalyzer - Extract IOCs from report") {
    SandboxEngine engine;
    auto& sa = engine.getSandboxAnalyzer();

    BehaviorReport report;
    report.sampleId = "TEST";
    report.networkConnections = {"192.168.1.1:80"};
    report.droppedFiles = {"malware.dll"};
    report.processesCreated = {"cmd.exe"};
    report.registryChanges = {"HKLM\\Run\\evil"};

    auto iocs = sa.extractIOCs(report);
    CHECK(iocs.size() == 4);
}

TEST_CASE("SandboxAnalyzer - Pattern matching") {
    SandboxEngine engine;
    auto& sa = engine.getSandboxAnalyzer();

    CHECK(sa.matchesPattern("launched cmd.exe /c whoami", "cmd.exe"));
    CHECK_FALSE(sa.matchesPattern("launched notepad.exe", "cmd.exe"));
}

TEST_CASE("SandboxAnalyzer - Enable/disable rules") {
    SandboxEngine engine;
    auto& sa = engine.getSandboxAnalyzer();

    auto rules = sa.getAnalysisRules();
    REQUIRE_FALSE(rules.empty());
    auto ruleId = rules[0].id;

    CHECK(sa.enableRule(ruleId, false));
    auto rule = sa.getRule(ruleId);
    CHECK_FALSE(rule->enabled);

    CHECK(sa.enableRule(ruleId, true));
    rule = sa.getRule(ruleId);
    CHECK(rule->enabled);
}
