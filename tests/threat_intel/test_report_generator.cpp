#include <doctest/doctest.h>
#include <threat_intel/IntelReportGenerator.h>

#include <nlohmann/json.hpp>
#include <chrono>
#include <string>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("IntelReportGenerator - Report generation") {
    IOCManager iocManager;
    ThreatCorrelationEngine correlationEngine;
    ThreatScoringEngine scoringEngine;
    IntelReportGenerator generator;

    // Add some IOCs
    auto now = std::chrono::system_clock::now();
    IOC ioc1;
    ioc1.type = IOCType::IP;
    ioc1.value = "192.168.1.1";
    ioc1.source = "feed_a";
    ioc1.confidence = 0.9;
    ioc1.severity = IOCSeverity::High;
    ioc1.lastSeen = now;
    ioc1.active = true;
    iocManager.addIOC(ioc1);

    IOC ioc2;
    ioc2.type = IOCType::Domain;
    ioc2.value = "evil.com";
    ioc2.source = "feed_b";
    ioc2.confidence = 0.7;
    ioc2.severity = IOCSeverity::Medium;
    ioc2.lastSeen = now;
    ioc2.active = true;
    iocManager.addIOC(ioc2);

    IOC ioc3;
    ioc3.type = IOCType::Hash_SHA256;
    ioc3.value = "deadbeef";
    ioc3.source = "feed_a";
    ioc3.confidence = 0.95;
    ioc3.severity = IOCSeverity::Critical;
    ioc3.lastSeen = now;
    ioc3.active = true;
    iocManager.addIOC(ioc3);

    SUBCASE("Generate report has required fields") {
        auto report = generator.generateReport(iocManager, correlationEngine, scoringEngine);

        CHECK(!report.id.empty());
        CHECK(!report.title.empty());
        CHECK(!report.summary.empty());
        CHECK(!report.sections.empty());
        CHECK(report.generatedAt != std::chrono::system_clock::time_point{});
    }

    SUBCASE("Report contains statistics") {
        auto report = generator.generateReport(iocManager, correlationEngine, scoringEngine);

        CHECK(report.statistics.count("total_iocs") > 0);
        CHECK(report.statistics["total_iocs"] == 3);
        CHECK(report.statistics.count("active_iocs") > 0);
    }

    SUBCASE("Report contains top threats") {
        auto report = generator.generateReport(iocManager, correlationEngine, scoringEngine);
        CHECK(!report.topThreats.empty());
        CHECK(report.topThreats.size() <= 10);
    }
}

TEST_CASE("IntelReportGenerator - Threat landscape") {
    IOCManager iocManager;
    IntelReportGenerator generator;

    IOC ip1, ip2, domain1;
    ip1.type = IOCType::IP; ip1.value = "1.2.3.4"; ip1.source = "s";
    ip1.severity = IOCSeverity::High;
    ip2.type = IOCType::IP; ip2.value = "5.6.7.8"; ip2.source = "s";
    ip2.severity = IOCSeverity::Low;
    domain1.type = IOCType::Domain; domain1.value = "test.com"; domain1.source = "s";
    domain1.severity = IOCSeverity::High;
    iocManager.addIOC(ip1);
    iocManager.addIOC(ip2);
    iocManager.addIOC(domain1);

    SUBCASE("Landscape section has type counts") {
        auto section = generator.generateThreatLandscape(iocManager);
        CHECK(section.title == "Threat Landscape");
        CHECK(section.data.count("type_IP") > 0);
        CHECK(section.data["type_IP"] == "2");
        CHECK(section.data.count("type_Domain") > 0);
        CHECK(section.data["type_Domain"] == "1");
        CHECK(section.data["total"] == "3");
    }

    SUBCASE("Landscape section has severity counts") {
        auto section = generator.generateThreatLandscape(iocManager);
        CHECK(section.data.count("severity_High") > 0);
        CHECK(section.data["severity_High"] == "2");
    }
}

TEST_CASE("IntelReportGenerator - Top threats") {
    IOCManager iocManager;
    ThreatScoringEngine scoringEngine;
    IntelReportGenerator generator;

    auto now = std::chrono::system_clock::now();

    IOC highConfidence;
    highConfidence.type = IOCType::IP;
    highConfidence.value = "10.0.0.1";
    highConfidence.source = "s";
    highConfidence.confidence = 0.99;
    highConfidence.lastSeen = now;
    highConfidence.active = true;
    iocManager.addIOC(highConfidence);

    IOC lowConfidence;
    lowConfidence.type = IOCType::IP;
    lowConfidence.value = "10.0.0.2";
    lowConfidence.source = "s";
    lowConfidence.confidence = 0.1;
    lowConfidence.lastSeen = now;
    lowConfidence.active = true;
    iocManager.addIOC(lowConfidence);

    SUBCASE("Top threats sorted by score descending") {
        auto top = generator.getTopThreats(iocManager, scoringEngine, 10);
        REQUIRE(top.size() == 2);
        // First should be higher confidence
        CHECK(top[0].confidence > top[1].confidence);
    }

    SUBCASE("Count parameter limits results") {
        auto top = generator.getTopThreats(iocManager, scoringEngine, 1);
        CHECK(top.size() == 1);
    }
}

TEST_CASE("IntelReportGenerator - Trending indicators") {
    IOCManager iocManager;
    IntelReportGenerator generator;

    auto now = std::chrono::system_clock::now();

    IOC recent;
    recent.type = IOCType::IP;
    recent.value = "10.0.0.1";
    recent.source = "s";
    recent.lastSeen = now;
    recent.active = true;
    iocManager.addIOC(recent);

    IOC old;
    old.type = IOCType::IP;
    old.value = "10.0.0.2";
    old.source = "s";
    old.lastSeen = now - std::chrono::hours(48);
    old.active = true;
    iocManager.addIOC(old);

    SUBCASE("Only recent IOCs returned within window") {
        auto trending = generator.getTrendingIndicators(iocManager, std::chrono::hours(24));
        CHECK(trending.size() == 1);
        CHECK(trending[0].value == "10.0.0.1");
    }
}

TEST_CASE("IntelReportGenerator - JSON serialization") {
    IOCManager iocManager;
    ThreatCorrelationEngine correlationEngine;
    ThreatScoringEngine scoringEngine;
    IntelReportGenerator generator;

    auto now = std::chrono::system_clock::now();
    IOC ioc;
    ioc.type = IOCType::IP;
    ioc.value = "10.0.0.1";
    ioc.source = "test";
    ioc.confidence = 0.8;
    ioc.severity = IOCSeverity::High;
    ioc.lastSeen = now;
    ioc.active = true;
    iocManager.addIOC(ioc);

    SUBCASE("toJson produces valid JSON object") {
        auto report = generator.generateReport(iocManager, correlationEngine, scoringEngine);
        auto json = generator.toJson(report);

        CHECK(json.contains("id"));
        CHECK(json.contains("title"));
        CHECK(json.contains("summary"));
        CHECK(json.contains("generatedAt"));
        CHECK(json.contains("sections"));
        CHECK(json.contains("topThreats"));
        CHECK(json.contains("trendingIndicators"));
        CHECK(json.contains("statistics"));
    }

    SUBCASE("JSON dump produces non-empty string") {
        auto report = generator.generateReport(iocManager, correlationEngine, scoringEngine);
        auto json = generator.toJson(report);
        std::string jsonStr = json.dump(2);
        CHECK(!jsonStr.empty());
        CHECK(jsonStr.find("id") != std::string::npos);
    }
}
