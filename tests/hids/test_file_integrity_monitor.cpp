#include <doctest/doctest.h>
#include <hids/FileIntegrityMonitor.h>

using namespace ThreatOne::HIDS;

TEST_CASE("FileIntegrityMonitor - Create baseline") {
    FileIntegrityMonitor fim;

    std::unordered_map<std::string, std::string> hashes;
    hashes["/etc/passwd"] = "abc123";
    hashes["/etc/shadow"] = "def456";

    auto id = fim.createBaseline("System Files", hashes);
    CHECK_FALSE(id.empty());

    auto info = fim.getBaseline(id);
    CHECK(info.name == "System Files");
    CHECK(info.fileCount == 2);
    CHECK(info.status == "Active");
}

TEST_CASE("FileIntegrityMonitor - Create baseline empty name fails") {
    FileIntegrityMonitor fim;
    std::unordered_map<std::string, std::string> hashes;
    auto id = fim.createBaseline("", hashes);
    CHECK(id.empty());
}

TEST_CASE("FileIntegrityMonitor - Get latest baseline") {
    FileIntegrityMonitor fim;
    std::unordered_map<std::string, std::string> hashes;
    hashes["/etc/test"] = "hash1";

    fim.createBaseline("First", hashes);
    fim.createBaseline("Second", hashes);

    auto latest = fim.getLatestBaseline();
    CHECK(latest.name == "Second");
}

TEST_CASE("FileIntegrityMonitor - List baselines") {
    FileIntegrityMonitor fim;
    std::unordered_map<std::string, std::string> hashes;

    fim.createBaseline("A", hashes);
    fim.createBaseline("B", hashes);

    auto baselines = fim.listBaselines();
    CHECK(baselines.size() == 2);
}

TEST_CASE("FileIntegrityMonitor - Delete baseline") {
    FileIntegrityMonitor fim;
    std::unordered_map<std::string, std::string> hashes;
    auto id = fim.createBaseline("ToDelete", hashes);

    CHECK(fim.deleteBaseline(id));
    CHECK_FALSE(fim.deleteBaseline("nonexistent"));
}

TEST_CASE("FileIntegrityMonitor - Compare to baseline detects modifications") {
    FileIntegrityMonitor fim;

    std::unordered_map<std::string, std::string> baseHashes;
    baseHashes["/etc/config"] = "original_hash";
    baseHashes["/etc/other"] = "other_hash";

    auto baselineId = fim.createBaseline("Base", baseHashes);

    std::unordered_map<std::string, std::string> currentHashes;
    currentHashes["/etc/config"] = "modified_hash";
    currentHashes["/etc/other"] = "other_hash";

    auto events = fim.compareToBaseline(baselineId, currentHashes);
    REQUIRE(events.size() == 1);
    CHECK(events[0].path == "/etc/config");
    CHECK(events[0].changeType == "modified");
}

TEST_CASE("FileIntegrityMonitor - Compare to baseline detects deletions") {
    FileIntegrityMonitor fim;

    std::unordered_map<std::string, std::string> baseHashes;
    baseHashes["/etc/file1"] = "hash1";
    baseHashes["/etc/file2"] = "hash2";

    auto id = fim.createBaseline("Base", baseHashes);

    std::unordered_map<std::string, std::string> current;
    current["/etc/file1"] = "hash1";

    auto events = fim.compareToBaseline(id, current);
    REQUIRE(events.size() == 1);
    CHECK(events[0].path == "/etc/file2");
    CHECK(events[0].changeType == "deleted");
}

TEST_CASE("FileIntegrityMonitor - Compare to baseline detects new files") {
    FileIntegrityMonitor fim;

    std::unordered_map<std::string, std::string> baseHashes;
    baseHashes["/etc/file1"] = "hash1";

    auto id = fim.createBaseline("Base", baseHashes);

    std::unordered_map<std::string, std::string> current;
    current["/etc/file1"] = "hash1";
    current["/etc/newfile"] = "newhash";

    auto events = fim.compareToBaseline(id, current);
    REQUIRE(events.size() == 1);
    CHECK(events[0].path == "/etc/newfile");
    CHECK(events[0].changeType == "created");
}

TEST_CASE("FileIntegrityMonitor - Add and remove monitored paths") {
    FileIntegrityMonitor fim;

    CHECK(fim.addMonitoredPath("/etc"));
    CHECK(fim.addMonitoredPath("/var/log"));
    CHECK_FALSE(fim.addMonitoredPath("/etc")); // duplicate
    CHECK_FALSE(fim.addMonitoredPath("")); // empty

    auto paths = fim.getMonitoredPaths();
    CHECK(paths.size() == 2);

    CHECK(fim.removeMonitoredPath("/etc"));
    CHECK_FALSE(fim.removeMonitoredPath("/nonexistent"));
}

TEST_CASE("FileIntegrityMonitor - File hash tracking") {
    FileIntegrityMonitor fim;

    fim.updateFileHash("/etc/passwd", "hash1");
    CHECK(fim.getFileHash("/etc/passwd") == "hash1");
    CHECK(fim.getFileHash("/nonexistent").empty());
    CHECK(fim.getTotalFilesMonitored() == 1);
}

TEST_CASE("FileIntegrityMonitor - Record file change") {
    FileIntegrityMonitor fim;

    fim.recordFileChange("/etc/test", "", "hash1");
    auto changes = fim.getFileChanges();
    REQUIRE(changes.size() == 1);
    CHECK(changes[0].action == "created");

    fim.recordFileChange("/etc/test", "hash1", "hash2");
    auto events = fim.getIntegrityEvents();
    CHECK(events.size() == 1);
    CHECK(events[0].changeType == "modified");
}

TEST_CASE("FileIntegrityMonitor - Monitoring rules") {
    FileIntegrityMonitor fim;

    MonitoringRule rule;
    rule.path = "/etc";
    rule.recursive = true;

    auto id = fim.addMonitoringRule(rule);
    CHECK_FALSE(id.empty());

    auto rules = fim.getMonitoringRules();
    CHECK(rules.size() == 1);

    CHECK(fim.removeMonitoringRule(id));
    CHECK_FALSE(fim.removeMonitoringRule("nonexistent"));
}
