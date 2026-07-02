#pragma once

#include "updates/IUpdateManager.h"
#include "core/Logger.h"

#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Updates {

struct BackupPoint {
    std::string id;
    std::string version;
    std::string createdAt;
    uint64_t sizeBytes = 0;
    std::string description;
    bool valid = true;
};

struct RollbackOperation {
    std::string id;
    std::string fromVersion;
    std::string toVersion;
    std::string performedAt;
    bool success = false;
    std::string errorMessage;
};

class RollbackManager {
public:
    RollbackManager();
    ~RollbackManager() = default;

    // Backup management
    std::string createBackupPoint(const std::string& version, const std::string& description = "");
    bool deleteBackupPoint(const std::string& backupId);
    [[nodiscard]] std::vector<BackupPoint> getBackupPoints() const;
    [[nodiscard]] std::optional<BackupPoint> getBackupPoint(const std::string& backupId) const;
    [[nodiscard]] std::optional<BackupPoint> getLatestBackup() const;

    // Rollback operations
    bool rollback(const std::string& fromVersion, const std::string& toVersion);
    bool rollbackToBackup(const std::string& backupId);
    [[nodiscard]] bool canRollback() const;
    [[nodiscard]] std::string getCurrentVersion() const;
    void setCurrentVersion(const std::string& version);

    // History
    [[nodiscard]] std::vector<RollbackOperation> getRollbackHistory() const;
    [[nodiscard]] uint64_t getRollbackCount() const;

    // Maintenance
    void pruneOldBackups(uint64_t maxBackups);
    void invalidateBackup(const std::string& backupId);
    [[nodiscard]] uint64_t getTotalBackupSize() const;

private:
    std::string generateBackupId();
    std::string generateOperationId();
    std::string getCurrentTimestamp() const;

    mutable std::mutex mutex_;
    std::vector<BackupPoint> backups_;
    std::vector<RollbackOperation> history_;
    std::string currentVersion_ = "1.0.0";
    int nextBackupId_ = 1;
    int nextOpId_ = 1;

    Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Updates
