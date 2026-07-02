#include <doctest/doctest.h>
#include <cloud/CloudSyncService.h>

using namespace ThreatOne::Cloud;

TEST_CASE("CloudSyncService - Basic sync") {
    CloudSyncService svc;
    CHECK(svc.performSync());
    CHECK(svc.getStatus() == SyncStatus::Idle);
    CHECK(svc.getTotalItemsSynced() > 0);
}

TEST_CASE("CloudSyncService - Sync with LocalWins resolution") {
    CloudSyncService svc;
    auto result = svc.performSyncWithResolution(ConflictResolution::LocalWins);
    CHECK(result.success);
    CHECK(result.itemsSynced == 10);
    CHECK(result.conflicts.empty());
    CHECK(svc.getStatus() == SyncStatus::Idle);
}

TEST_CASE("CloudSyncService - Sync with RemoteWins resolution") {
    CloudSyncService svc;
    auto result = svc.performSyncWithResolution(ConflictResolution::RemoteWins);
    CHECK(result.success);
    CHECK(result.itemsSynced == 10);
    CHECK(svc.getStatus() == SyncStatus::Idle);
}

TEST_CASE("CloudSyncService - Sync with Manual resolution creates conflicts") {
    CloudSyncService svc;
    auto result = svc.performSyncWithResolution(ConflictResolution::Manual);
    CHECK_FALSE(result.success);
    CHECK(result.itemsSynced == 5);
    CHECK(result.conflicts.size() == 2);
    CHECK(svc.getStatus() == SyncStatus::Conflict);
}

TEST_CASE("CloudSyncService - Delta submission and apply") {
    CloudSyncService svc;

    SyncDelta delta;
    delta.resourceId = "res-001";
    delta.operation = "update";
    delta.data = "{\"key\":\"value\"}";

    std::string id = svc.submitDelta(delta);
    CHECK_FALSE(id.empty());

    auto pending = svc.getPendingDeltas();
    CHECK(pending.size() == 1);
    CHECK(pending[0].resourceId == "res-001");

    CHECK(svc.applyDelta(id));
    CHECK(svc.getPendingDeltas().empty());
}

TEST_CASE("CloudSyncService - Apply nonexistent delta fails") {
    CloudSyncService svc;
    CHECK_FALSE(svc.applyDelta("nonexistent"));
}

TEST_CASE("CloudSyncService - Sync clears pending deltas") {
    CloudSyncService svc;

    SyncDelta delta;
    delta.resourceId = "res-001";
    delta.operation = "create";
    svc.submitDelta(delta);

    svc.performSync();
    CHECK(svc.getPendingDeltas().empty());
}

TEST_CASE("CloudSyncService - Conflict detection and resolution") {
    CloudSyncService svc;

    // Generate conflicts via manual sync
    svc.performSyncWithResolution(ConflictResolution::Manual);

    auto conflicts = svc.detectConflicts();
    CHECK(conflicts.size() == 2);

    CHECK(svc.resolveConflict("config_policy_v2", ConflictResolution::LocalWins));
    CHECK(svc.detectConflicts().size() == 1);

    CHECK(svc.resolveConflict("endpoint_settings_v3", ConflictResolution::RemoteWins));
    CHECK(svc.detectConflicts().empty());
    CHECK(svc.getStatus() == SyncStatus::Idle);
}

TEST_CASE("CloudSyncService - Resolve nonexistent conflict fails") {
    CloudSyncService svc;
    CHECK_FALSE(svc.resolveConflict("nonexistent", ConflictResolution::LocalWins));
}

TEST_CASE("CloudSyncService - Last sync time updates") {
    CloudSyncService svc;
    CHECK(svc.getLastSyncTime().empty());
    svc.performSync();
    CHECK_FALSE(svc.getLastSyncTime().empty());
}
