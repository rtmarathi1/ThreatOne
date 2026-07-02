#include <doctest/doctest.h>
#include <hids/LogAnalyzer.h>

using namespace ThreatOne::HIDS;

TEST_CASE("LogAnalyzer - Add and get patterns") {
    LogAnalyzer la;

    LogPattern pattern;
    pattern.name = "Failed Login";
    pattern.pattern = "failed.*login";
    pattern.severity = "high";
    pattern.enabled = true;

    auto id = la.addPattern(pattern);
    CHECK_FALSE(id.empty());

    auto patterns = la.getPatterns();
    CHECK(patterns.size() == 1);
    CHECK(patterns[0].name == "Failed Login");
}

TEST_CASE("LogAnalyzer - Add pattern empty regex fails") {
    LogAnalyzer la;
    LogPattern p;
    p.name = "Empty";
    p.pattern = "";
    CHECK(la.addPattern(p).empty());
}

TEST_CASE("LogAnalyzer - Add pattern invalid regex fails") {
    LogAnalyzer la;
    LogPattern p;
    p.name = "Bad";
    p.pattern = "[invalid";
    CHECK(la.addPattern(p).empty());
}

TEST_CASE("LogAnalyzer - Remove pattern") {
    LogAnalyzer la;
    LogPattern p;
    p.name = "Test";
    p.pattern = "test";
    auto id = la.addPattern(p);

    CHECK(la.removePattern(id));
    CHECK_FALSE(la.removePattern("nonexistent"));
    CHECK(la.getPatterns().empty());
}

TEST_CASE("LogAnalyzer - Enable and disable patterns") {
    LogAnalyzer la;
    LogPattern p;
    p.name = "Test";
    p.pattern = "test";
    p.enabled = true;
    auto id = la.addPattern(p);

    CHECK(la.disablePattern(id));
    CHECK(la.getActivePatternCount() == 0);

    CHECK(la.enablePattern(id));
    CHECK(la.getActivePatternCount() == 1);

    CHECK_FALSE(la.enablePattern("invalid"));
    CHECK_FALSE(la.disablePattern("invalid"));
}

TEST_CASE("LogAnalyzer - Pattern matching on ingestion") {
    LogAnalyzer la;

    LogPattern p;
    p.name = "Error";
    p.pattern = "error";
    p.severity = "high";
    p.enabled = true;
    la.addPattern(p);

    SystemLogEntry entry;
    entry.source = "app";
    entry.message = "An error occurred in module X";
    entry.level = "error";
    la.ingestEntry(entry);

    auto matched = la.getMatchedEntries();
    REQUIRE(matched.size() == 1);
    CHECK(matched[0].matched == true);
}

TEST_CASE("LogAnalyzer - Non-matching entries") {
    LogAnalyzer la;

    LogPattern p;
    p.name = "Error";
    p.pattern = "critical_failure";
    p.enabled = true;
    la.addPattern(p);

    SystemLogEntry entry;
    entry.source = "app";
    entry.message = "Normal operation";
    la.ingestEntry(entry);

    CHECK(la.getMatchedEntries().empty());
}

TEST_CASE("LogAnalyzer - Disabled patterns do not match") {
    LogAnalyzer la;

    LogPattern p;
    p.name = "Error";
    p.pattern = "error";
    p.enabled = false;
    la.addPattern(p);

    SystemLogEntry entry;
    entry.source = "app";
    entry.message = "An error occurred";
    la.ingestEntry(entry);

    CHECK(la.getMatchedEntries().empty());
}

TEST_CASE("LogAnalyzer - Recent entries") {
    LogAnalyzer la;

    for (int i = 0; i < 5; ++i) {
        SystemLogEntry entry;
        entry.source = "app";
        entry.message = "Entry " + std::to_string(i);
        la.ingestEntry(entry);
    }

    auto recent = la.getRecentEntries(3);
    CHECK(recent.size() == 3);
}

TEST_CASE("LogAnalyzer - Anomaly detection with frequency spike") {
    LogAnalyzer la;
    la.setAnomalyThreshold(1.5);

    // Create spike from one source
    for (int i = 0; i < 100; ++i) {
        SystemLogEntry entry;
        entry.source = "suspicious_source";
        entry.message = "event " + std::to_string(i);
        la.ingestEntry(entry);
    }

    // Add minimal entries from other sources to create clear disparity
    for (int i = 0; i < 3; ++i) {
        SystemLogEntry normalEntry;
        normalEntry.source = "normal_source_" + std::to_string(i);
        normalEntry.message = "normal event";
        la.ingestEntry(normalEntry);
    }

    auto anomalies = la.detectAnomalies();
    CHECK(!anomalies.empty());
}

TEST_CASE("LogAnalyzer - Stats tracking") {
    LogAnalyzer la;

    LogPattern p;
    p.name = "Test";
    p.pattern = "match";
    p.enabled = true;
    la.addPattern(p);

    SystemLogEntry entry;
    entry.source = "app";
    entry.message = "should match this";
    la.ingestEntry(entry);

    auto stats = la.getStats();
    CHECK(stats.totalEntriesProcessed == 1);
    CHECK(stats.totalMatches == 1);
    CHECK(stats.activePatterns == 1);
}

TEST_CASE("LogAnalyzer - Reset stats") {
    LogAnalyzer la;

    SystemLogEntry entry;
    entry.source = "app";
    entry.message = "test";
    la.ingestEntry(entry);

    la.resetStats();
    auto stats = la.getStats();
    CHECK(stats.totalEntriesProcessed == 0);
}
