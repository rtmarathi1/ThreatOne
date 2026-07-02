#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace ThreatOne::Cloud {

struct CloudStatus {
    bool connected = false;
    std::string lastSync;
    std::string accountId;
    uint64_t storageUsed = 0;
    uint64_t storageTotal = 0;
};

struct BackupInfo {
    std::string id;
    std::string name;
    std::string timestamp;
    uint64_t size = 0;
    bool encrypted = false;
};

enum class SyncStatus {
    Idle,
    Syncing,
    Conflict,
    Error
};

struct SyncResult {
    bool success = false;
    int itemsSynced = 0;
    std::vector<std::string> conflicts;
    std::string timestamp;
};

struct PolicyInfo {
    std::string id;
    std::string name;
    int version = 1;
    std::string content;
    std::string distributedAt;
    std::vector<std::string> acknowledgedBy;
};

enum class ConflictResolution {
    LocalWins,
    RemoteWins,
    Manual
};

struct BackupSchedule {
    std::string id;
    std::string name;
    std::string frequency;
    int retention = 7;
    bool encrypted = false;
    std::string lastRun;
    std::string nextRun;
};

class ICloudManager {
public:
    virtual ~ICloudManager() = default;

    // Basic sync and status
    virtual bool sync() = 0;
    virtual SyncResult syncWithConflictResolution(ConflictResolution resolution) = 0;
    virtual SyncStatus getSyncStatus() = 0;
    virtual CloudStatus getStatus() = 0;

    // Backup management
    virtual bool backup(const std::string& name) = 0;
    virtual bool restore(const std::string& backupId) = 0;
    virtual std::vector<BackupInfo> listBackups() = 0;
    virtual bool deleteBackup(const std::string& backupId) = 0;

    // Policy distribution
    virtual std::string distributePolicy(const PolicyInfo& policy) = 0;
    virtual std::vector<PolicyInfo> getPolicies() = 0;
    virtual bool acknowledgePolicy(const std::string& policyId, const std::string& endpointId) = 0;

    // Backup schedules
    virtual std::string createBackupSchedule(const BackupSchedule& schedule) = 0;
    virtual std::vector<BackupSchedule> getBackupSchedules() = 0;

    // Threat intel and policies (legacy)
    virtual bool uploadThreatIntel(const std::string& data) = 0;
    virtual std::string downloadPolicies() = 0;
};

} // namespace ThreatOne::Cloud
