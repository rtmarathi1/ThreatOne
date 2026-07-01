#include <doctest/doctest.h>
#include <ai/RiskScoringEngine.h>

#include <string>

using namespace ThreatOne::AI;

TEST_CASE("RiskScoringEngine - weighted score calculation") {
    RiskScoringEngine engine;

    SUBCASE("All zeros gives zero score") {
        RiskFactors factors;
        factors.fileReputation = 0.0;
        factors.behaviorScore = 0.0;
        factors.networkRisk = 0.0;
        factors.vulnerabilityScore = 0.0;

        auto result = engine.calculateRisk(factors);
        CHECK(result.overallScore == doctest::Approx(0.0).epsilon(0.01));
        CHECK(result.riskLevel == "minimal");
    }

    SUBCASE("All 100 gives 100 score") {
        RiskFactors factors;
        factors.fileReputation = 100.0;
        factors.behaviorScore = 100.0;
        factors.networkRisk = 100.0;
        factors.vulnerabilityScore = 100.0;

        auto result = engine.calculateRisk(factors);
        CHECK(result.overallScore == doctest::Approx(100.0).epsilon(0.01));
        CHECK(result.riskLevel == "critical");
    }

    SUBCASE("Weighted calculation with default weights") {
        // Default weights: file=0.3, behavior=0.3, network=0.2, vulnerability=0.2
        RiskFactors factors;
        factors.fileReputation = 100.0;
        factors.behaviorScore = 0.0;
        factors.networkRisk = 0.0;
        factors.vulnerabilityScore = 0.0;

        auto result = engine.calculateRisk(factors);
        // Expected: 100*0.3 + 0*0.3 + 0*0.2 + 0*0.2 = 30
        CHECK(result.overallScore == doctest::Approx(30.0).epsilon(0.01));
    }

    SUBCASE("Mixed scores produce correct weighted result") {
        RiskFactors factors;
        factors.fileReputation = 50.0;
        factors.behaviorScore = 80.0;
        factors.networkRisk = 40.0;
        factors.vulnerabilityScore = 60.0;

        auto result = engine.calculateRisk(factors);
        // Expected: 50*0.3 + 80*0.3 + 40*0.2 + 60*0.2 = 15 + 24 + 8 + 12 = 59
        CHECK(result.overallScore == doctest::Approx(59.0).epsilon(0.01));
    }
}

TEST_CASE("RiskScoringEngine - custom weights") {
    RiskScoringEngine engine;

    SUBCASE("Custom weights change calculation") {
        RiskWeights customWeights;
        customWeights.file = 1.0;
        customWeights.behavior = 0.0;
        customWeights.network = 0.0;
        customWeights.vulnerability = 0.0;
        engine.setWeights(customWeights);

        RiskFactors factors;
        factors.fileReputation = 75.0;
        factors.behaviorScore = 100.0;
        factors.networkRisk = 100.0;
        factors.vulnerabilityScore = 100.0;

        auto result = engine.calculateRisk(factors);
        CHECK(result.overallScore == doctest::Approx(75.0).epsilon(0.01));
    }

    SUBCASE("getWeights returns the set weights") {
        RiskWeights custom;
        custom.file = 0.4;
        custom.behavior = 0.3;
        custom.network = 0.2;
        custom.vulnerability = 0.1;
        engine.setWeights(custom);

        auto retrieved = engine.getWeights();
        CHECK(retrieved.file == doctest::Approx(0.4));
        CHECK(retrieved.behavior == doctest::Approx(0.3));
        CHECK(retrieved.network == doctest::Approx(0.2));
        CHECK(retrieved.vulnerability == doctest::Approx(0.1));
    }
}

TEST_CASE("RiskScoringEngine - risk level boundaries") {
    SUBCASE("Minimal: 0-20") {
        CHECK(RiskScoringEngine::getRiskLevel(0.0) == "minimal");
        CHECK(RiskScoringEngine::getRiskLevel(10.0) == "minimal");
        CHECK(RiskScoringEngine::getRiskLevel(20.0) == "minimal");
    }

    SUBCASE("Low: 21-40") {
        CHECK(RiskScoringEngine::getRiskLevel(21.0) == "low");
        CHECK(RiskScoringEngine::getRiskLevel(30.0) == "low");
        CHECK(RiskScoringEngine::getRiskLevel(40.0) == "low");
    }

    SUBCASE("Medium: 41-60") {
        CHECK(RiskScoringEngine::getRiskLevel(41.0) == "medium");
        CHECK(RiskScoringEngine::getRiskLevel(50.0) == "medium");
        CHECK(RiskScoringEngine::getRiskLevel(60.0) == "medium");
    }

    SUBCASE("High: 61-80") {
        CHECK(RiskScoringEngine::getRiskLevel(61.0) == "high");
        CHECK(RiskScoringEngine::getRiskLevel(70.0) == "high");
        CHECK(RiskScoringEngine::getRiskLevel(80.0) == "high");
    }

    SUBCASE("Critical: 81-100") {
        CHECK(RiskScoringEngine::getRiskLevel(81.0) == "critical");
        CHECK(RiskScoringEngine::getRiskLevel(90.0) == "critical");
        CHECK(RiskScoringEngine::getRiskLevel(100.0) == "critical");
    }
}

TEST_CASE("RiskScoringEngine - breakdown accuracy") {
    RiskScoringEngine engine;

    SUBCASE("Breakdown sums to overall score") {
        RiskFactors factors;
        factors.fileReputation = 60.0;
        factors.behaviorScore = 40.0;
        factors.networkRisk = 80.0;
        factors.vulnerabilityScore = 20.0;

        auto result = engine.calculateRisk(factors);
        double sum = 0.0;
        for (const auto& [key, value] : result.breakdown) {
            sum += value;
        }
        CHECK(sum == doctest::Approx(result.overallScore).epsilon(0.01));
    }

    SUBCASE("Contributing factors identified for high scores") {
        RiskFactors factors;
        factors.fileReputation = 90.0;  // Above 50 threshold
        factors.behaviorScore = 20.0;   // Below 50 threshold
        factors.networkRisk = 70.0;     // Above 50 threshold
        factors.vulnerabilityScore = 10.0; // Below 50 threshold

        auto result = engine.calculateRisk(factors);
        // fileReputation and networkRisk should be contributing factors
        bool hasFile = false;
        bool hasNetwork = false;
        for (const auto& f : result.contributingFactors) {
            if (f == "fileReputation") hasFile = true;
            if (f == "networkRisk") hasNetwork = true;
        }
        CHECK(hasFile == true);
        CHECK(hasNetwork == true);
    }
}
