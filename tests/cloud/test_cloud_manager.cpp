#include <doctest/doctest.h>
#include <cloud/CloudManager.h>

using namespace ThreatOne::Cloud;

TEST_CASE("CloudManager - Basic sync") {
    CloudManager mgr;

    CHECK(mgr.sync());

    auto status = mgr.getStatus();
    CHECK(status.connected);
    CHECK_FALSE(status.lastSync.empty());
}

TEST_CASE("CloudManager - Sync status starts idle") {
    CloudManager mgr;
    CHECK(mgr.getSyncStatus() == SyncStatus::Idle);
}

TEST_CASE("CloudManager - Sync with LocalWins resolution") {
    CloudManager mgr;

    auto result = mgr.syncWithConflictResolution(ConflictResolution::LocalWins);
    CHECK(result.success);
    CHECK(result.itemsSynced == 10);
    CHECK(result.conflicts.empty());
    CHECK_FALSE(result.timestamp.empty());
    CHECK(mgr.getSyncStatus() == SyncStatus::Idle);
}

TEST_CASE("CloudManager - Sync with RemoteWins resolution") {
    CloudManager mgr;

    auto result = mgr.syncWithConflictResolution(ConflictResolution::RemoteWins);
    CHECK(result.success);
    CHECK(result.itemsSynced == 10);
    CHECK(result.conflicts.empty());
    CHECK(mgr.getSyncStatus() == SyncStatus::Idle);
}

TEST_CASE("CloudManager - Sync with Manual resolution generates conflicts") {
    CloudManager mgr;

    auto result = mgr.syncWithConflictResolution(ConflictResolution::Manual);
    CHECK_FALSE(result.success);
    CHECK(result.itemsSynced == 5);
    CHECK(result.conflicts.size() == 2);
    CHECK(mgr.getSyncStatus() == SyncStatus::Conflict);
}

TEST_CASE("CloudManager - Backup and list") {
    CloudManager mgr;

    CHECK(mgr.backup("daily-backup-001"));
    CHECK(mgr.backup("daily-backup-002"));

    auto backups = mgr.listBackups();
    CHECK(backups.size() == 2);
    CHECK(backups[0].name == "daily-backup-001");
    CHECK(backups[1].name == "daily-backup-002");
    CHECK_FALSE(backups[0].id.empty());
}

TEST_CASE("CloudManager - Restore backup") {
    CloudManager mgr;

    mgr.backup("restore-test");
    auto backups = mgr.listBackups();
    REQUIRE(backups.size() == 1);

    CHECK(mgr.restore(backups[0].id));
}

TEST_CASE("CloudManager - Restore nonexistent backup fails") {
    CloudManager mgr;
    CHECK_FALSE(mgr.restore("nonexistent"));
}

TEST_CASE("CloudManager - Delete backup") {
    CloudManager mgr;

    mgr.backup("to-delete");
    auto backups = mgr.listBackups();
    REQUIRE(backups.size() == 1);
    std::string id = backups[0].id;

    CHECK(mgr.deleteBackup(id));
    CHECK(mgr.listBackups().empty());
}

TEST_CASE("CloudManager - Delete nonexistent backup fails") {
    CloudManager mgr;
    CHECK_FALSE(mgr.deleteBackup("nonexistent"));
}

TEST_CASE("CloudManager - Distribute policy") {
    CloudManager mgr;

    PolicyInfo policy;
    policy.name = "Antivirus Config";
    policy.version = 1;
    policy.content = "{\"scan_interval\": 3600}";

    std::string id = mgr.distributePolicy(policy);
    CHECK_FALSE(id.empty());
    CHECK(id.find("POL-") == 0);

    auto policies = mgr.getPolicies();
    CHECK(policies.size() == 1);
    CHECK(policies[0].name == "Antivirus Config");
    CHECK(policies[0].version == 1);
    CHECK_FALSE(policies[0].distributedAt.empty());
}

TEST_CASE("CloudManager - Distribute multiple policies") {
    CloudManager mgr;

    PolicyInfo p1;
    p1.name = "Firewall Rules";
    p1.version = 2;

    PolicyInfo p2;
    p2.name = "EDR Config";
    p2.version = 1;

    std::string id1 = mgr.distributePolicy(p1);
    std::string id2 = mgr.distributePolicy(p2);

    CHECK(id1 != id2);
    CHECK(mgr.getPolicies().size() == 2);
}

TEST_CASE("CloudManager - Acknowledge policy") {
    CloudManager mgr;

    PolicyInfo policy;
    policy.name = "Test Policy";
    policy.version = 1;
    std::string policyId = mgr.distributePolicy(policy);

    CHECK(mgr.acknowledgePolicy(policyId, "endpoint-001"));
    CHECK(mgr.acknowledgePolicy(policyId, "endpoint-002"));

    auto policies = mgr.getPolicies();
    REQUIRE(policies.size() == 1);
    CHECK(policies[0].acknowledgedBy.size() == 2);
    CHECK(policies[0].acknowledgedBy[0] == "endpoint-001");
    CHECK(policies[0].acknowledgedBy[1] == "endpoint-002");
}

TEST_CASE("CloudManager - Acknowledge policy idempotent") {
    CloudManager mgr;

    PolicyInfo policy;
    policy.name = "Idempotent Policy";
    std::string policyId = mgr.distributePolicy(policy);

    CHECK(mgr.acknowledgePolicy(policyId, "endpoint-001"));
    CHECK(mgr.acknowledgePolicy(policyId, "endpoint-001")); // Same endpoint again

    auto policies = mgr.getPolicies();
    REQUIRE(policies.size() == 1);
    CHECK(policies[0].acknowledgedBy.size() == 1);
}

TEST_CASE("CloudManager - Acknowledge nonexistent policy fails") {
    CloudManager mgr;
    CHECK_FALSE(mgr.acknowledgePolicy("nonexistent", "endpoint-001"));
}

TEST_CASE("CloudManager - Create backup schedule") {
    CloudManager mgr;

    BackupSchedule sched;
    sched.name = "Nightly Backup";
    sched.frequency = "daily";
    sched.retention = 30;
    sched.encrypted = true;
    sched.nextRun = "2024-01-16T02:00:00";

    std::string id = mgr.createBackupSchedule(sched);
    CHECK_FALSE(id.empty());
    CHECK(id.find("SCHED-") == 0);

    auto schedules = mgr.getBackupSchedules();
    CHECK(schedules.size() == 1);
    CHECK(schedules[0].name == "Nightly Backup");
    CHECK(schedules[0].frequency == "daily");
    CHECK(schedules[0].retention == 30);
    CHECK(schedules[0].encrypted);
}

TEST_CASE("CloudManager - Create multiple backup schedules") {
    CloudManager mgr;

    BackupSchedule s1;
    s1.name = "Daily";
    s1.frequency = "daily";
    s1.retention = 7;

    BackupSchedule s2;
    s2.name = "Weekly";
    s2.frequency = "weekly";
    s2.retention = 30;

    std::string id1 = mgr.createBackupSchedule(s1);
    std::string id2 = mgr.createBackupSchedule(s2);

    CHECK(id1 != id2);
    CHECK(mgr.getBackupSchedules().size() == 2);
}

TEST_CASE("CloudManager - Get status reflects storage usage") {
    CloudManager mgr;

    auto status = mgr.getStatus();
    CHECK(status.storageUsed == 0);

    mgr.backup("test-backup");

    status = mgr.getStatus();
    CHECK(status.storageUsed > 0);
    CHECK(status.storageTotal == 1073741824);
    CHECK(status.accountId == "cloud-account-001");
}

TEST_CASE("CloudManager - Upload threat intel") {
    CloudManager mgr;
    CHECK(mgr.uploadThreatIntel("{\"iocs\":[\"1.2.3.4\"]}"));
}

TEST_CASE("CloudManager - Download policies") {
    CloudManager mgr;

    PolicyInfo policy;
    policy.name = "Test";
    mgr.distributePolicy(policy);

    std::string result = mgr.downloadPolicies();
    CHECK(result.find("policies") != std::string::npos);
    CHECK(result.find("Test") != std::string::npos);
}

TEST_CASE("CloudManager - Download policies when empty") {
    CloudManager mgr;
    std::string result = mgr.downloadPolicies();
    CHECK(result == "{\"policies\":[]}");
}
