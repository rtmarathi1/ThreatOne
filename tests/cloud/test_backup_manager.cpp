#include <doctest/doctest.h>
#include <cloud/BackupManager.h>

using namespace ThreatOne::Cloud;

TEST_CASE("CloudBackupManager - Create and list backups") {
    CloudBackupManager mgr;

    std::string id1 = mgr.createBackup("daily-001");
    std::string id2 = mgr.createBackup("daily-002");
    CHECK_FALSE(id1.empty());
    CHECK(id1 != id2);

    auto backups = mgr.listBackups();
    CHECK(backups.size() == 2);
    CHECK(backups[0].name == "daily-001");
    CHECK(backups[1].name == "daily-002");
}

TEST_CASE("CloudBackupManager - Restore backup") {
    CloudBackupManager mgr;
    std::string id = mgr.createBackup("test-restore");
    CHECK(mgr.restoreBackup(id));
}

TEST_CASE("CloudBackupManager - Restore nonexistent fails") {
    CloudBackupManager mgr;
    CHECK_FALSE(mgr.restoreBackup("nonexistent"));
}

TEST_CASE("CloudBackupManager - Delete backup") {
    CloudBackupManager mgr;
    std::string id = mgr.createBackup("to-delete");
    CHECK(mgr.deleteBackup(id));
    CHECK(mgr.listBackups().empty());
}

TEST_CASE("CloudBackupManager - Delete nonexistent fails") {
    CloudBackupManager mgr;
    CHECK_FALSE(mgr.deleteBackup("nonexistent"));
}

TEST_CASE("CloudBackupManager - Create and get schedules") {
    CloudBackupManager mgr;

    BackupSchedule sched;
    sched.name = "Nightly";
    sched.frequency = "daily";
    sched.retention = 30;

    std::string id = mgr.createSchedule(sched);
    CHECK_FALSE(id.empty());
    CHECK(id.find("SCHED-") == 0);

    auto schedules = mgr.getSchedules();
    CHECK(schedules.size() == 1);
    CHECK(schedules[0].name == "Nightly");
}

TEST_CASE("CloudBackupManager - Delete schedule") {
    CloudBackupManager mgr;

    BackupSchedule sched;
    sched.name = "Weekly";
    sched.frequency = "weekly";
    std::string id = mgr.createSchedule(sched);

    CHECK(mgr.deleteSchedule(id));
    CHECK(mgr.getSchedules().empty());
}

TEST_CASE("CloudBackupManager - Verify backup") {
    CloudBackupManager mgr;
    std::string id = mgr.createBackup("verify-test");

    auto verification = mgr.verifyBackup(id);
    CHECK(verification.backupId == id);
    CHECK(verification.integrityValid);
    CHECK(verification.checksum > 0);
}

TEST_CASE("CloudBackupManager - Verify nonexistent backup") {
    CloudBackupManager mgr;
    auto v = mgr.verifyBackup("nonexistent");
    CHECK_FALSE(v.integrityValid);
}

TEST_CASE("CloudBackupManager - Set encryption") {
    CloudBackupManager mgr;
    std::string id = mgr.createBackup("encrypt-test");

    CHECK(mgr.setEncryption(id, true));
    auto backups = mgr.listBackups();
    CHECK(backups[0].encrypted);
}

TEST_CASE("CloudBackupManager - Retention policy") {
    CloudBackupManager mgr;
    mgr.createBackup("backup-1");
    mgr.createBackup("backup-2");
    mgr.createBackup("backup-3");

    int removed = mgr.applyRetentionPolicy(2);
    CHECK(removed == 1);
    CHECK(mgr.listBackups().size() == 2);
}

TEST_CASE("CloudBackupManager - Total storage used") {
    CloudBackupManager mgr;
    CHECK(mgr.getTotalStorageUsed() == 0);
    mgr.createBackup("test");
    CHECK(mgr.getTotalStorageUsed() > 0);
}
