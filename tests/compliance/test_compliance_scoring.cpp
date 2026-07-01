#include <doctest/doctest.h>
#include <compliance/ComplianceScoring.h>
#include <compliance/ComplianceFramework.h>
#include <compliance/ComplianceScanner.h>

using namespace ThreatOne::Compliance;

TEST_CASE("ComplianceScoring - calculate framework score") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);
    ComplianceScoring scoring;

    SystemState state;
    // Make all NIST-ID controls pass
    state.enabledFeatures.push_back("NIST-ID");
    state.installedPolicies.push_back("NIST-ID");

    auto result = scanner.scan(Framework::NIST, state);
    REQUIRE(result.isOk());

    auto categories = framework.getCategories(Framework::NIST);
    auto score = scoring.calculateScore(Framework::NIST, result.value(), categories);

    CHECK(score.framework == Framework::NIST);
    CHECK(score.overallScore >= 0.0);
    CHECK(score.overallScore <= 100.0);
    CHECK(score.categoryScores.size() == 5);
    CHECK_FALSE(score.timestamp.empty());
}

TEST_CASE("ComplianceScoring - per-category scores") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);
    ComplianceScoring scoring;

    SystemState state;
    // Make all controls in one category pass
    for (int i = 1; i <= 5; i++) {
        state.configurations["NIST-ID-" + std::to_string(i) + ".status"] = "pass";
    }

    auto result = scanner.scan(Framework::NIST, state);
    REQUIRE(result.isOk());

    auto categories = framework.getCategories(Framework::NIST);
    auto score = scoring.calculateScore(Framework::NIST, result.value(), categories);

    // Find the ID category score - it should be 100%
    for (const auto& catScore : score.categoryScores) {
        if (catScore.categoryId == "NIST-ID") {
            CHECK(catScore.score == doctest::Approx(100.0));
            CHECK(catScore.passingControls == 5);
            CHECK(catScore.totalControls == 5);
        }
    }
}

TEST_CASE("ComplianceScoring - overall score across frameworks") {
    ComplianceScoring scoring;

    std::vector<FrameworkScore> scores;
    FrameworkScore s1;
    s1.framework = Framework::NIST;
    s1.overallScore = 80.0;
    scores.push_back(s1);

    FrameworkScore s2;
    s2.framework = Framework::SOC2;
    s2.overallScore = 60.0;
    scores.push_back(s2);

    double overall = scoring.calculateOverallScore(scores);
    CHECK(overall == doctest::Approx(70.0));
}

TEST_CASE("ComplianceScoring - empty scores returns zero") {
    ComplianceScoring scoring;
    std::vector<FrameworkScore> empty;
    CHECK(scoring.calculateOverallScore(empty) == doctest::Approx(0.0));
}

TEST_CASE("ComplianceScoring - trend tracking") {
    ComplianceScoring scoring;

    scoring.recordScore(Framework::NIST, 75.0);
    scoring.recordScore(Framework::NIST, 80.0);
    scoring.recordScore(Framework::NIST, 85.0);

    auto history = scoring.getScoreHistory(Framework::NIST);
    REQUIRE(history.size() == 3);
    CHECK(history[0].score == doctest::Approx(75.0));
    CHECK(history[1].score == doctest::Approx(80.0));
    CHECK(history[2].score == doctest::Approx(85.0));
    CHECK_FALSE(history[0].timestamp.empty());
}

TEST_CASE("ComplianceScoring - get latest score") {
    ComplianceScoring scoring;

    auto noScore = scoring.getLatestScore(Framework::NIST);
    CHECK_FALSE(noScore.has_value());

    scoring.recordScore(Framework::NIST, 70.0);
    scoring.recordScore(Framework::NIST, 85.0);

    auto latest = scoring.getLatestScore(Framework::NIST);
    REQUIRE(latest.has_value());
    CHECK(latest.value() == doctest::Approx(85.0));
}

TEST_CASE("ComplianceScoring - clear history") {
    ComplianceScoring scoring;

    scoring.recordScore(Framework::NIST, 75.0);
    scoring.recordScore(Framework::SOC2, 80.0);

    scoring.clearHistory(Framework::NIST);
    CHECK(scoring.getScoreHistory(Framework::NIST).empty());
    CHECK_FALSE(scoring.getScoreHistory(Framework::SOC2).empty());

    scoring.clearAllHistory();
    CHECK(scoring.getScoreHistory(Framework::SOC2).empty());
}

TEST_CASE("ComplianceScoring - all pass gives 100 percent") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);
    ComplianceScoring scoring;

    SystemState state;
    // Make all PCI controls pass
    auto controls = framework.getControls(Framework::PCI_DSS);
    for (const auto& ctrl : controls) {
        state.configurations[ctrl.id + ".status"] = "pass";
    }

    auto result = scanner.scan(Framework::PCI_DSS, state);
    REQUIRE(result.isOk());

    auto categories = framework.getCategories(Framework::PCI_DSS);
    auto score = scoring.calculateScore(Framework::PCI_DSS, result.value(), categories);
    CHECK(score.overallScore == doctest::Approx(100.0));
}

TEST_CASE("ComplianceScoring - all fail gives 0 percent") {
    ComplianceFramework framework;
    ComplianceScanner scanner(framework);
    ComplianceScoring scoring;

    SystemState state;
    // Make all controls fail explicitly
    auto controls = framework.getControls(Framework::PCI_DSS);
    for (const auto& ctrl : controls) {
        state.configurations[ctrl.id + ".status"] = "fail";
    }

    auto result = scanner.scan(Framework::PCI_DSS, state);
    REQUIRE(result.isOk());

    auto categories = framework.getCategories(Framework::PCI_DSS);
    auto score = scoring.calculateScore(Framework::PCI_DSS, result.value(), categories);
    CHECK(score.overallScore == doctest::Approx(0.0));
}
