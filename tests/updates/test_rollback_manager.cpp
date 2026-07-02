#include <doctest/doctest.h>
#include <updates/UpdateManager.h>

using namespace ThreatOne::Updates;

TEST_CASE("RollbackManager - Create backup point") {
    UpdateManager mgr;
    auto& rb = mgr.getRollbackManager();

    auto id = rb.createBackupPoint("1.0.0", "Before update");
    CHECK_FALSE(id.empty());
    CHECK(id.find("BKP-") == 0);

    auto bp = rb.getBackupPoint(id);
    REQUIRE(bp.has_value());
    CHECK(bp->version == "1.0.0");
    CHECK(bp->valid == true);
}

TEST_CASE("RollbackManager - Rollback to previous version") {
    UpdateManager mgr;
    auto& rb = mgr.getRollbackManager();

    rb.setCurrentVersion("2.0.0");
    rb.createBackupPoint("1.0.0");

    CHECK(rb.rollback("2.0.0", "1.0.0"));
    CHECK(rb.getCurrentVersion() == "1.0.0");
}

TEST_CASE("RollbackManager - Rollback to backup") {
    UpdateManager mgr;
    auto& rb = mgr.getRollbackManager();

    rb.setCurrentVersion("2.0.0");
    auto bkpId = rb.createBackupPoint("1.5.0");

    CHECK(rb.rollbackToBackup(bkpId));
    CHECK(rb.getCurrentVersion() == "1.5.0");
}

TEST_CASE("RollbackManager - Can rollback check") {
    UpdateManager mgr;
    auto& rb = mgr.getRollbackManager();

    rb.setCurrentVersion("2.0.0");
    CHECK_FALSE(rb.canRollback());

    rb.createBackupPoint("1.0.0");
    CHECK(rb.canRollback());
}

TEST_CASE("RollbackManager - Rollback history") {
    UpdateManager mgr;
    auto& rb = mgr.getRollbackManager();

    rb.rollback("2.0.0", "1.0.0");
    rb.rollback("1.0.0", "0.9.0");

    auto history = rb.getRollbackHistory();
    CHECK(history.size() == 2);
    CHECK(rb.getRollbackCount() == 2);
}

TEST_CASE("RollbackManager - Prune old backups") {
    UpdateManager mgr;
    auto& rb = mgr.getRollbackManager();

    rb.createBackupPoint("1.0.0");
    rb.createBackupPoint("1.1.0");
    rb.createBackupPoint("1.2.0");

    rb.pruneOldBackups(2);
    CHECK(rb.getBackupPoints().size() == 2);
}

TEST_CASE("RollbackManager - Invalidate backup") {
    UpdateManager mgr;
    auto& rb = mgr.getRollbackManager();

    auto id = rb.createBackupPoint("1.0.0");
    rb.invalidateBackup(id);

    auto bp = rb.getBackupPoint(id);
    CHECK_FALSE(bp->valid);
    CHECK_FALSE(rb.rollbackToBackup(id));
}
