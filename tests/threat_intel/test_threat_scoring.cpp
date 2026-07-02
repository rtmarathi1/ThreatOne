#include <doctest/doctest.h>
#include <threat_intel/ThreatScoring.h>

#include <chrono>
#include <string>
#include <unordered_map>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("ThreatScoringEngine - Score calculation") {
    ThreatScoringEngine engine;

    SUBCASE("High confidence IOC gets high score") {
        IOC ioc;
        ioc.type = IOCType::IP;
        ioc.value = "10.0.0.1";
        ioc.confidence = 0.95;
        ioc.source = "reliable_source";
        ioc.lastSeen = std::chrono::system_clock::now();

        engine.setSourceReliability("reliable_source", 0.9);

        auto score = engine.calculateScore(ioc);
        CHECK(score.overallScore > 50.0);
        CHECK(score.overallScore <= 100.0);
        CHECK(score.iocConfidence > 0.0);
    }

    SUBCASE("Low confidence IOC gets low score") {
        IOC ioc;
        ioc.type = IOCType::Domain;
        ioc.value = "maybe-bad.com";
        ioc.confidence = 0.1;
        ioc.source = "unreliable";
        ioc.lastSeen = std::chrono::system_clock::now();

        engine.setSourceReliability("unreliable", 0.2);

        auto score = engine.calculateScore(ioc);
        CHECK(score.overallScore < 20.0);
    }

    SUBCASE("Score is in range 0-100") {
        IOC ioc;
        ioc.type = IOCType::IP;
        ioc.value = "10.0.0.1";
        ioc.confidence = 0.5;
        ioc.source = "test";
        ioc.lastSeen = std::chrono::system_clock::now();

        auto score = engine.calculateScore(ioc);
        CHECK(score.overallScore >= 0.0);
        CHECK(score.overallScore <= 100.0);
    }
}

TEST_CASE("ThreatScoringEngine - Age decay") {
    ThreatScoringEngine engine;

    SUBCASE("Recent IOC has minimal decay") {
        IOC recent;
        recent.type = IOCType::IP;
        recent.value = "10.0.0.1";
        recent.confidence = 0.8;
        recent.source = "test";
        recent.lastSeen = std::chrono::system_clock::now();

        auto score = engine.calculateScore(recent);
        CHECK(score.ageDecay >= 0.95);
    }

    SUBCASE("Old IOC has significant decay") {
        IOC old;
        old.type = IOCType::IP;
        old.value = "10.0.0.2";
        old.confidence = 0.8;
        old.source = "test";
        old.lastSeen = std::chrono::system_clock::now() - std::chrono::hours(24 * 60);

        auto score = engine.calculateScore(old);
        CHECK(score.ageDecay < 0.5);
    }

    SUBCASE("Age decay is between 0 and 1") {
        IOC ioc;
        ioc.type = IOCType::Domain;
        ioc.value = "test.com";
        ioc.confidence = 0.5;
        ioc.source = "test";
        ioc.lastSeen = std::chrono::system_clock::now() - std::chrono::hours(24 * 30);

        auto score = engine.calculateScore(ioc);
        CHECK(score.ageDecay >= 0.0);
        CHECK(score.ageDecay <= 1.0);
    }
}

TEST_CASE("ThreatScoringEngine - Source reliability") {
    ThreatScoringEngine engine;

    SUBCASE("Set and get source reliability") {
        engine.setSourceReliability("intel_feed", 0.9);
        CHECK(engine.getSourceReliability("intel_feed") == doctest::Approx(0.9));
    }

    SUBCASE("Unknown source defaults to 0.5") {
        CHECK(engine.getSourceReliability("unknown") == doctest::Approx(0.5));
    }

    SUBCASE("Source reliability affects score") {
        IOC ioc;
        ioc.type = IOCType::IP;
        ioc.value = "10.0.0.1";
        ioc.confidence = 0.8;
        ioc.lastSeen = std::chrono::system_clock::now();

        ioc.source = "reliable";
        engine.setSourceReliability("reliable", 1.0);
        auto highScore = engine.calculateScore(ioc);

        ioc.source = "unreliable";
        engine.setSourceReliability("unreliable", 0.1);
        auto lowScore = engine.calculateScore(ioc);

        CHECK(highScore.overallScore > lowScore.overallScore);
    }
}

TEST_CASE("ThreatScoringEngine - Correlation boost") {
    ThreatScoringEngine engine;

    SUBCASE("Correlated IOC gets boost") {
        IOC ioc;
        ioc.type = IOCType::IP;
        ioc.value = "10.0.0.1";
        ioc.confidence = 0.7;
        ioc.source = "test";
        ioc.lastSeen = std::chrono::system_clock::now();

        auto scoreWithout = engine.calculateScore(ioc, false, 0.0);
        auto scoreWith = engine.calculateScore(ioc, true, 0.8);

        CHECK(scoreWith.overallScore > scoreWithout.overallScore);
        CHECK(scoreWith.correlationBoost > 0.0);
        CHECK(scoreWithout.correlationBoost == doctest::Approx(0.0));
    }

    SUBCASE("Higher correlation strength gives bigger boost") {
        IOC ioc;
        ioc.type = IOCType::Domain;
        ioc.value = "test.com";
        ioc.confidence = 0.6;
        ioc.source = "test";
        ioc.lastSeen = std::chrono::system_clock::now();

        auto weakCorrelation = engine.calculateScore(ioc, true, 0.2);
        auto strongCorrelation = engine.calculateScore(ioc, true, 0.9);

        CHECK(strongCorrelation.correlationBoost > weakCorrelation.correlationBoost);
    }
}

TEST_CASE("ThreatScoringEngine - Weight configuration") {
    ThreatScoringEngine engine;

    SUBCASE("Set individual weight") {
        engine.setWeight("custom_factor", 2.5);
        CHECK(engine.getWeight("custom_factor") == doctest::Approx(2.5));
    }

    SUBCASE("Configure multiple weights") {
        std::unordered_map<std::string, double> weights;
        weights["confidence"] = 1.5;
        weights["source"] = 0.6;
        engine.configureWeights(weights);

        CHECK(engine.getWeight("confidence") == doctest::Approx(1.5));
        CHECK(engine.getWeight("source") == doctest::Approx(0.6));
    }

    SUBCASE("Default weight for unknown factor") {
        CHECK(engine.getWeight("nonexistent") == doctest::Approx(1.0));
    }
}
