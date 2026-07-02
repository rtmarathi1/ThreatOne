#pragma once

#include "cloud/ICloudManager.h"
#include "core/Logger.h"

#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Cloud {

struct SyncDelta {
    std::string id;
    std::string resourceId;
    std::string operation;  // "create", "update", "delete"
    std::string data;
    std::string timestamp;
    uint64_t version = 0;
};

struct ConflictInfo {
    std::string resourceId;
    std::string localVersion;
    std::string remoteVersion;
    std::string description;
};

class CloudSyncService {
public:
    CloudSyncService();
    ~CloudSyncService() = default;

    // Core sync operations
    bool performSync();
    SyncResult performSyncWithResolution(ConflictResolution resolution);
    [[nodiscard]] SyncStatus getStatus() const;

    // Delta and incremental sync
    std::string submitDelta(const SyncDelta& delta);
    [[nodiscard]] std::vector<SyncDelta> getPendingDeltas() const;
    bool applyDelta(const std::string& deltaId);
    void clearAppliedDeltas();

    // Conflict management
    [[nodiscard]] std::vector<ConflictInfo> detectConflicts() const;
    bool resolveConflict(const std::string& resourceId, ConflictResolution resolution);

    // Metrics
    [[nodiscard]] int getTotalItemsSynced() const;
    [[nodiscard]] std::string getLastSyncTime() const;

private:
    std::string generateDeltaId();

    mutable std::mutex mutex_;
    SyncStatus status_ = SyncStatus::Idle;
    int totalItemsSynced_ = 0;
    std::string lastSyncTime_;
    std::map<std::string, SyncDelta> pendingDeltas_;
    std::map<std::string, SyncDelta> appliedDeltas_;
    std::map<std::string, ConflictInfo> conflicts_;
    int nextDeltaId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Cloud
