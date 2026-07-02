#include <doctest/doctest.h>
#include <threat_intel/ThreatCorrelation.h>

#include <chrono>
#include <vector>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("ThreatCorrelationEngine - Same source forms campaign") {
    ThreatCorrelationEngine engine;

    CorrelationRule rule;
    rule.name = "same_source_rule";
    rule.timeWindow = std::chrono::seconds(3600);
    rule.minIOCs = 2;
    engine.addCorrelationRule(rule);

    auto now = std::chrono::system_clock::now();

    std::vector<IOC> iocs;
    IOC ioc1;
    ioc1.id = 1;
    ioc1.type = IOCType::IP;
    ioc1.value = "10.0.0.1";
    ioc1.source = "APT_feed";
    ioc1.confidence = 0.8;
    ioc1.firstSeen = now;
    ioc1.lastSeen = now;
    iocs.push_back(ioc1);

    IOC ioc2;
    ioc2.id = 2;
    ioc2.type = IOCType::Domain;
    ioc2.value = "c2.evil.com";
    ioc2.source = "APT_feed";
    ioc2.confidence = 0.9;
    ioc2.firstSeen = now + std::chrono::minutes(10);
    ioc2.lastSeen = now + std::chrono::minutes(10);
    iocs.push_back(ioc2);

    auto campaigns = engine.correlateIOCs(iocs);
    REQUIRE(!campaigns.empty());
    CHECK(campaigns[0].iocIds.size() >= 2);
    CHECK(campaigns[0].confidence > 0.0);
}

TEST_CASE("ThreatCorrelationEngine - Outside time window no campaign") {
    ThreatCorrelationEngine engine;

    CorrelationRule rule;
    rule.name = "tight_window";
    rule.timeWindow = std::chrono::seconds(60); // 1 minute
    rule.minIOCs = 2;
    engine.addCorrelationRule(rule);

    auto now = std::chrono::system_clock::now();

    std::vector<IOC> iocs;
    IOC ioc1;
    ioc1.id = 1;
    ioc1.type = IOCType::IP;
    ioc1.value = "10.0.0.1";
    ioc1.source = "feed1";
    ioc1.firstSeen = now;
    ioc1.lastSeen = now;
    iocs.push_back(ioc1);

    IOC ioc2;
    ioc2.id = 2;
    ioc2.type = IOCType::IP;
    ioc2.value = "10.0.0.2";
    ioc2.source = "feed1";
    ioc2.firstSeen = now + std::chrono::hours(2);
    ioc2.lastSeen = now + std::chrono::hours(2);
    iocs.push_back(ioc2);

    auto campaigns = engine.correlateIOCs(iocs);
    CHECK(campaigns.empty());
}

TEST_CASE("ThreatCorrelationEngine - Insufficient IOCs no campaign") {
    ThreatCorrelationEngine engine;

    CorrelationRule rule;
    rule.name = "needs_three";
    rule.timeWindow = std::chrono::seconds(3600);
    rule.minIOCs = 3;
    engine.addCorrelationRule(rule);

    auto now = std::chrono::system_clock::now();
    std::vector<IOC> iocs;

    IOC ioc1;
    ioc1.id = 1;
    ioc1.type = IOCType::IP;
    ioc1.value = "10.0.0.1";
    ioc1.source = "src";
    ioc1.firstSeen = now;
    ioc1.lastSeen = now;
    iocs.push_back(ioc1);

    IOC ioc2;
    ioc2.id = 2;
    ioc2.type = IOCType::IP;
    ioc2.value = "10.0.0.2";
    ioc2.source = "src";
    ioc2.firstSeen = now;
    ioc2.lastSeen = now;
    iocs.push_back(ioc2);

    auto campaigns = engine.correlateIOCs(iocs);
    CHECK(campaigns.empty());
}

TEST_CASE("ThreatCorrelationEngine - Scoring campaigns") {
    ThreatCorrelationEngine engine;

    Campaign small;
    small.iocIds = {1, 2};
    small.confidence = 0.7;
    small.firstSeen = std::chrono::system_clock::now();
    small.lastSeen = std::chrono::system_clock::now() + std::chrono::minutes(30);

    Campaign large;
    large.iocIds = {1, 2, 3, 4, 5, 6, 7, 8};
    large.confidence = 0.7;
    large.firstSeen = std::chrono::system_clock::now();
    large.lastSeen = std::chrono::system_clock::now() + std::chrono::minutes(30);

    double smallScore = engine.calculateCorrelationScore(small);
    double largeScore = engine.calculateCorrelationScore(large);
    CHECK(largeScore > smallScore);
    CHECK(smallScore >= 0.0);
    CHECK(smallScore <= 1.0);
    CHECK(largeScore >= 0.0);
    CHECK(largeScore <= 1.0);
}

TEST_CASE("ThreatCorrelationEngine - Find related IOCs by source") {
    ThreatCorrelationEngine engine;

    auto now = std::chrono::system_clock::now();

    std::vector<IOC> iocs;
    IOC ioc1;
    ioc1.id = 1;
    ioc1.type = IOCType::IP;
    ioc1.value = "10.0.0.1";
    ioc1.source = "shared_source";
    ioc1.firstSeen = now;
    ioc1.lastSeen = now;
    iocs.push_back(ioc1);

    IOC ioc2;
    ioc2.id = 2;
    ioc2.type = IOCType::Domain;
    ioc2.value = "evil.com";
    ioc2.source = "shared_source";
    ioc2.firstSeen = now;
    ioc2.lastSeen = now;
    iocs.push_back(ioc2);

    IOC ioc3;
    ioc3.id = 3;
    ioc3.type = IOCType::IP;
    ioc3.value = "10.0.0.2";
    ioc3.source = "other_source";
    ioc3.firstSeen = now + std::chrono::hours(48);
    ioc3.lastSeen = now + std::chrono::hours(48);
    iocs.push_back(ioc3);

    auto relationships = engine.findRelatedIOCs(1, iocs);
    CHECK(!relationships.empty());
    bool foundSameSource = false;
    for (const auto& rel : relationships) {
        if (rel.relatedIOCId == 2 && rel.relationshipType == "same_source") {
            foundSameSource = true;
        }
    }
    CHECK(foundSameSource);
}

TEST_CASE("ThreatCorrelationEngine - Non-existent IOC empty relationships") {
    ThreatCorrelationEngine engine;

    std::vector<IOC> iocs;
    IOC ioc1;
    ioc1.id = 1;
    ioc1.type = IOCType::IP;
    ioc1.value = "10.0.0.1";
    ioc1.source = "s";
    iocs.push_back(ioc1);

    auto relationships = engine.findRelatedIOCs(999, iocs);
    CHECK(relationships.empty());
}

TEST_CASE("ThreatCorrelationEngine - Rule management") {
    ThreatCorrelationEngine engine;
    CHECK(engine.ruleCount() == 0);

    CorrelationRule r1;
    r1.name = "rule1";
    r1.minIOCs = 2;
    engine.addCorrelationRule(r1);

    CorrelationRule r2;
    r2.name = "rule2";
    r2.minIOCs = 3;
    engine.addCorrelationRule(r2);

    CHECK(engine.ruleCount() == 2);
    auto rules = engine.getRules();
    CHECK(rules.size() == 2);
}
