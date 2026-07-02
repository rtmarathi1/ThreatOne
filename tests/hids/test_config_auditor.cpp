#include <doctest/doctest.h>
#include <hids/ConfigAuditor.h>

using namespace ThreatOne::HIDS;

TEST_CASE("ConfigAuditor - Add config file") {
    ConfigAuditor auditor;

    ConfigFile config;
    config.path = "/etc/ssh/sshd_config";
    config.description = "SSH daemon configuration";
    config.expectedHash = "abc123";

    auto id = auditor.addConfigFile(config);
    CHECK_FALSE(id.empty());

    auto configs = auditor.getConfigFiles();
    CHECK(configs.size() == 1);
    CHECK(configs[0].path == "/etc/ssh/sshd_config");
}

TEST_CASE("ConfigAuditor - Add config file empty path fails") {
    ConfigAuditor auditor;
    ConfigFile config;
    config.path = "";
    CHECK(auditor.addConfigFile(config).empty());
}

TEST_CASE("ConfigAuditor - Remove config file") {
    ConfigAuditor auditor;
    ConfigFile config;
    config.path = "/etc/test";
    auto id = auditor.addConfigFile(config);

    CHECK(auditor.removeConfigFile(id));
    CHECK_FALSE(auditor.removeConfigFile("nonexistent"));
    CHECK(auditor.getConfigFiles().empty());
}

TEST_CASE("ConfigAuditor - Update expected hash") {
    ConfigAuditor auditor;
    ConfigFile config;
    config.path = "/etc/test";
    config.expectedHash = "old_hash";
    auto id = auditor.addConfigFile(config);

    CHECK(auditor.updateExpectedHash(id, "new_hash"));
    auto c = auditor.getConfigFile(id);
    CHECK(c.expectedHash == "new_hash");

    CHECK_FALSE(auditor.updateExpectedHash("nonexistent", "hash"));
}

TEST_CASE("ConfigAuditor - Run audit detects hash mismatch") {
    ConfigAuditor auditor;

    ConfigFile config;
    config.path = "/etc/important.conf";
    config.expectedHash = "expected_hash";
    config.currentHash = "different_hash";
    config.monitored = true;
    auto id = auditor.addConfigFile(config);

    auto results = auditor.runAudit();
    REQUIRE(results.size() == 1);
    CHECK_FALSE(results[0].compliant);
    CHECK(results[0].severity == ConfigSeverity::High);
}

TEST_CASE("ConfigAuditor - Run audit passes when hashes match") {
    ConfigAuditor auditor;

    ConfigFile config;
    config.path = "/etc/good.conf";
    config.expectedHash = "same_hash";
    config.currentHash = "same_hash";
    config.monitored = true;
    auditor.addConfigFile(config);

    auto results = auditor.runAudit();
    REQUIRE(results.size() == 1);
    CHECK(results[0].compliant);
}

TEST_CASE("ConfigAuditor - Unmonitored files skipped") {
    ConfigAuditor auditor;

    ConfigFile config;
    config.path = "/etc/skip.conf";
    config.monitored = false;
    auditor.addConfigFile(config);

    auto results = auditor.runAudit();
    CHECK(results.empty());
}

TEST_CASE("ConfigAuditor - Get changed configs") {
    ConfigAuditor auditor;

    ConfigFile config;
    config.path = "/etc/changed.conf";
    config.expectedHash = "hash1";
    config.currentHash = "hash2";
    auditor.addConfigFile(config);

    ConfigFile unchanged;
    unchanged.path = "/etc/ok.conf";
    unchanged.expectedHash = "same";
    unchanged.currentHash = "same";
    auditor.addConfigFile(unchanged);

    auto changed = auditor.getChangedConfigs();
    CHECK(changed.size() == 1);
    CHECK(changed[0].path == "/etc/changed.conf");
}

TEST_CASE("ConfigAuditor - Acknowledge change") {
    ConfigAuditor auditor;

    ConfigFile config;
    config.path = "/etc/test.conf";
    config.expectedHash = "old";
    config.currentHash = "new";
    auto id = auditor.addConfigFile(config);

    CHECK(auditor.acknowledgeChange(id));
    auto c = auditor.getConfigFile(id);
    CHECK(c.expectedHash == "new");
    CHECK_FALSE(auditor.acknowledgeChange("nonexistent"));
}

TEST_CASE("ConfigAuditor - Summary") {
    ConfigAuditor auditor;

    ConfigFile good;
    good.path = "/etc/good.conf";
    good.expectedHash = "same";
    good.currentHash = "same";
    good.monitored = true;
    auditor.addConfigFile(good);

    ConfigFile bad;
    bad.path = "/etc/bad.conf";
    bad.expectedHash = "expected";
    bad.currentHash = "actual";
    bad.monitored = true;
    auditor.addConfigFile(bad);

    auditor.runAudit();

    auto summary = auditor.getSummary();
    CHECK(summary.totalConfigs == 2);
    CHECK(summary.compliant == 1);
    CHECK(summary.nonCompliant == 1);
    CHECK(summary.changed == 1);
}

TEST_CASE("ConfigAuditor - Clear results") {
    ConfigAuditor auditor;
    ConfigFile config;
    config.path = "/etc/test";
    config.monitored = true;
    auditor.addConfigFile(config);
    auditor.runAudit();

    CHECK_FALSE(auditor.getAuditResults().empty());
    auditor.clearResults();
    CHECK(auditor.getAuditResults().empty());
}

TEST_CASE("ConfigAuditor - Total audits counter") {
    ConfigAuditor auditor;
    CHECK(auditor.getTotalAuditsRun() == 0);
    auditor.runAudit();
    CHECK(auditor.getTotalAuditsRun() == 1);
}
