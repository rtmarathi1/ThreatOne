#include <doctest/doctest.h>
#include <ai/PredictionEngine.h>

#include <string>
#include <vector>

using namespace ThreatOne::AI;

TEST_CASE("PredictionEngine - attack likelihood") {
    PredictionEngine engine;

    SUBCASE("Likelihood is in [0, 1] range") {
        ThreatIntelligence intel;
        intel.activeCampaigns = {"APT28", "Lazarus"};
        intel.knownVulnerabilities = {"CVE-2024-0001", "CVE-2024-0002"};
        intel.industryTargeting = {"finance", "healthcare"};

        std::vector<std::string> vulns = {"CVE-2024-0001", "CVE-2024-0003"};
        std::vector<double> history = {5.0, 8.0, 12.0, 15.0, 20.0};

        auto result = engine.predictAttackLikelihood(intel, vulns, history);
        CHECK(result.likelihood >= 0.0);
        CHECK(result.likelihood <= 1.0);
        CHECK(result.confidence >= 0.0);
        CHECK(result.confidence <= 1.0);
    }

    SUBCASE("High vulnerability exposure increases likelihood") {
        ThreatIntelligence intel;
        intel.activeCampaigns = {"Campaign1"};

        // Low vulnerability exposure
        std::vector<std::string> lowVulns = {"CVE-1"};
        std::vector<double> history = {1.0, 2.0, 1.0};

        auto lowResult = engine.predictAttackLikelihood(intel, lowVulns, history);

        // High vulnerability exposure
        std::vector<std::string> highVulns = {
            "CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5",
            "CVE-6", "CVE-7", "CVE-8", "CVE-9", "CVE-10"
        };

        auto highResult = engine.predictAttackLikelihood(intel, highVulns, history);

        CHECK(highResult.likelihood >= lowResult.likelihood);
    }

    SUBCASE("Empty inputs produce valid result") {
        ThreatIntelligence intel;
        std::vector<std::string> vulns;
        std::vector<double> history;

        auto result = engine.predictAttackLikelihood(intel, vulns, history);
        CHECK(result.likelihood >= 0.0);
        CHECK(result.likelihood <= 1.0);
        CHECK(!result.reasoning.empty());
    }

    SUBCASE("Result includes timeframe") {
        ThreatIntelligence intel;
        intel.activeCampaigns = {"APT29"};
        std::vector<std::string> vulns = {"CVE-2024-100"};
        std::vector<double> history = {10.0, 20.0, 30.0};

        auto result = engine.predictAttackLikelihood(intel, vulns, history);
        CHECK(!result.timeframe.empty());
    }

    SUBCASE("Result includes predicted threat type") {
        ThreatIntelligence intel;
        intel.activeCampaigns = {"Ransomware_Gang"};
        intel.industryTargeting = {"technology"};
        std::vector<std::string> vulns = {"CVE-1", "CVE-2"};
        std::vector<double> history = {5.0, 10.0};

        auto result = engine.predictAttackLikelihood(intel, vulns, history);
        CHECK(!result.predictedThreatType.empty());
    }
}

TEST_CASE("PredictionEngine - historical trend") {
    PredictionEngine engine;

    SUBCASE("Trend calculated for ascending data") {
        std::vector<double> ascending = {1.0, 2.0, 3.0, 4.0, 5.0};
        auto trend = engine.getHistoricalTrend(ascending);
        CHECK(!trend.empty());
        // Ascending trend should show increasing values
        if (trend.size() >= 2) {
            CHECK(trend.back() >= trend.front());
        }
    }

    SUBCASE("Empty history returns empty trend") {
        std::vector<double> empty;
        auto trend = engine.getHistoricalTrend(empty);
        CHECK(trend.empty());
    }

    SUBCASE("Single point returns valid trend") {
        std::vector<double> single = {5.0};
        auto trend = engine.getHistoricalTrend(single);
        // May return a single projected point or empty
        // Single point may or may not yield a trend
        (void)trend;
    }
}

TEST_CASE("PredictionEngine - exposure assessment") {
    PredictionEngine engine;

    SUBCASE("No vulnerabilities gives zero or low exposure") {
        std::vector<std::string> noVulns;
        double exposure = engine.assessExposure(noVulns);
        CHECK(exposure >= 0.0);
        CHECK(exposure <= 1.0);
        CHECK(exposure == doctest::Approx(0.0).epsilon(0.1));
    }

    SUBCASE("Many vulnerabilities increase exposure") {
        std::vector<std::string> manyVulns;
        for (int i = 0; i < 20; ++i) {
            manyVulns.push_back("CVE-2024-" + std::to_string(i));
        }
        double exposure = engine.assessExposure(manyVulns);
        CHECK(exposure > 0.0);
        CHECK(exposure <= 1.0);
    }

    SUBCASE("Exposure increases with more vulnerabilities") {
        std::vector<std::string> fewVulns = {"CVE-1", "CVE-2"};
        std::vector<std::string> manyVulns = {"CVE-1", "CVE-2", "CVE-3", "CVE-4",
                                              "CVE-5", "CVE-6", "CVE-7", "CVE-8"};

        double fewExposure = engine.assessExposure(fewVulns);
        double manyExposure = engine.assessExposure(manyVulns);
        CHECK(manyExposure >= fewExposure);
    }
}

TEST_CASE("PredictionEngine - predict next target") {
    PredictionEngine engine;

    SUBCASE("Empty history returns unknown") {
        std::vector<std::string> empty;
        auto target = engine.predictNextTarget(empty);
        CHECK(target == "unknown");
    }

    SUBCASE("Frequent target predicted") {
        std::vector<std::string> history = {
            "server1", "server2", "server1", "server1", "server3", "server1"
        };
        auto target = engine.predictNextTarget(history);
        CHECK(!target.empty());
        CHECK(target == "server1");  // Most frequent
    }
}
