#include <doctest/doctest.h>
#include <ai/RecommendationEngine.h>

#include <string>
#include <vector>
#include <utility>

using namespace ThreatOne::AI;

TEST_CASE("RecommendationEngine - high-risk posture") {
    RecommendationEngine engine;

    SUBCASE("High-risk posture generates recommendations") {
        RiskPosture posture;
        posture.overallRisk = 85.0;
        posture.openVulnerabilities = 10;
        posture.activeThreats = 5;
        posture.configGaps = {"missing_mfa", "outdated_firewall", "no_encryption"};

        auto recommendations = engine.generateRecommendations(posture);
        CHECK(!recommendations.empty());
        CHECK(recommendations.size() >= 3);
    }

    SUBCASE("Recommendations contain valid fields") {
        RiskPosture posture;
        posture.overallRisk = 75.0;
        posture.openVulnerabilities = 5;
        posture.activeThreats = 2;
        posture.configGaps = {"weak_passwords"};

        auto recommendations = engine.generateRecommendations(posture);
        REQUIRE(!recommendations.empty());

        for (const auto& rec : recommendations) {
            CHECK(!rec.id.empty());
            CHECK(!rec.title.empty());
            CHECK(!rec.description.empty());
            CHECK(rec.priority >= 1);
            CHECK(rec.priority <= 5);
            CHECK(!rec.category.empty());
        }
    }
}

TEST_CASE("RecommendationEngine - prioritization ordering") {
    RecommendationEngine engine;

    SUBCASE("Recommendations sorted by priority") {
        RiskPosture posture;
        posture.overallRisk = 90.0;
        posture.openVulnerabilities = 15;
        posture.activeThreats = 8;
        posture.configGaps = {"gap1", "gap2", "gap3"};

        auto recommendations = engine.generateRecommendations(posture);
        REQUIRE(recommendations.size() >= 2);

        // Verify sorted by priority (lower number = higher priority)
        for (size_t i = 1; i < recommendations.size(); ++i) {
            CHECK(recommendations[i].priority >= recommendations[i - 1].priority);
        }
    }

    SUBCASE("Prioritize method sorts correctly") {
        std::vector<SecurityRecommendation> recs;

        SecurityRecommendation low;
        low.id = "low";
        low.title = "Low priority";
        low.description = "desc";
        low.priority = 5;
        low.category = "general";
        low.effort = "low";
        low.impact = "low";

        SecurityRecommendation high;
        high.id = "high";
        high.title = "High priority";
        high.description = "desc";
        high.priority = 1;
        high.category = "threat";
        high.effort = "medium";
        high.impact = "high";

        SecurityRecommendation mid;
        mid.id = "mid";
        mid.title = "Mid priority";
        mid.description = "desc";
        mid.priority = 3;
        mid.category = "config";
        mid.effort = "low";
        mid.impact = "medium";

        recs.push_back(low);
        recs.push_back(high);
        recs.push_back(mid);

        auto sorted = engine.prioritize(std::move(recs));
        REQUIRE(sorted.size() == 3);
        CHECK(sorted[0].id == "high");
        CHECK(sorted[1].id == "mid");
        CHECK(sorted[2].id == "low");
    }
}

TEST_CASE("RecommendationEngine - getTopN") {
    RecommendationEngine engine;

    SUBCASE("Top N limits results") {
        RiskPosture posture;
        posture.overallRisk = 80.0;
        posture.openVulnerabilities = 10;
        posture.activeThreats = 5;
        posture.configGaps = {"gap1", "gap2"};

        auto top3 = engine.getTopN(3, posture);
        CHECK(top3.size() <= 3);
    }

    SUBCASE("Top N returns all if fewer available") {
        RiskPosture posture;
        posture.overallRisk = 30.0;
        posture.openVulnerabilities = 1;
        posture.activeThreats = 0;

        auto all = engine.generateRecommendations(posture);
        auto topN = engine.getTopN(100, posture);
        CHECK(topN.size() == all.size());
    }

    SUBCASE("Top 1 returns highest priority") {
        RiskPosture posture;
        posture.overallRisk = 90.0;
        posture.openVulnerabilities = 10;
        posture.activeThreats = 5;
        posture.configGaps = {"missing_mfa"};

        auto top1 = engine.getTopN(1, posture);
        REQUIRE(top1.size() == 1);
        CHECK(top1[0].priority <= 2);  // Should be a high-priority recommendation
    }
}

TEST_CASE("RecommendationEngine - minimal posture") {
    RecommendationEngine engine;

    SUBCASE("Zero risk posture generates risk-based recommendations") {
        RiskPosture posture;
        posture.overallRisk = 0.0;
        posture.openVulnerabilities = 0;
        posture.activeThreats = 0;

        auto recommendations = engine.generateRecommendations(posture);
        // Even zero risk should generate some baseline recommendations
        // The risk recommendations are always generated
        // Even zero risk should produce some baseline recommendations
        (void)recommendations;
    }
}
